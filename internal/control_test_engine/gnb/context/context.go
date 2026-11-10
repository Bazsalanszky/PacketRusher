/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 * © Copyright 2026 Valentin D'Emmanuele
 */
package context

import (
	"encoding/hex"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"my5G-RANTester/config"
	"my5G-RANTester/internal/control_test_engine/gnb/gtp"
	ngapCodec "my5G-RANTester/lib/ngap"

	nasType "github.com/free5gc/nas/ie"
	"github.com/free5gc/ngap/aper"

	ngapType "github.com/free5gc/ngap/ie"

	"github.com/ishidawataru/sctp"
	log "my5G-RANTester/internal/log"
)

type GNBContext struct {
	dataInfo       DataInfo    // gnb data plane information
	controlInfo    ControlInfo // gnb control plane information
	uePool         sync.Map    // map[int64]*GNBUe, UeRanNgapId as key
	prUePool       sync.Map    // map[int64]*GNBUe, PrUeId as key
	amfPool        sync.Map    // map[int64]*GNBAmf, AmfId as key
	teidPool       sync.Map    // map[uint32]*GNBUe, downlinkTeid as key
	sliceInfo      Slice
	idUeGenerator  atomic.Int64  // ran UE id, incremented atomically.
	idAmfGenerator atomic.Int64  // ran amf id, incremented atomically.
	teidGenerator  atomic.Uint32 // ran UE downlink Teid, incremented atomically.
	ueIpGenerator  uint8         // ran ue ip.
	pagedUEs       []PagedUE
	pagedUELock    sync.Mutex
	gtpDevice      atomic.Pointer[gtp.Device] // GTP-U device shared by this gNB's UEs, if any
}

type DataInfo struct {
	gnbIpPort    netip.AddrPort // gnb ip and port for data plane.
	ipv6         netip.Addr     // its IPv6 address too, when the gNB is dual-stack on N3
	preferIPv6   bool           // towards a UPF that signals both IP versions
	advertiseAll bool           // signal every N3 address, not only the one in use
}

type Slice struct {
	sd  string
	sst string
}

type ControlInfo struct {
	mcc            string
	mnc            string
	tac            string
	gnbId          string
	identity       config.GNBIdentity
	gnbIpPort      netip.AddrPort
	ipv6           netip.Addr // its IPv6 address too, when the gNB is dual-stack on N2
	inboundChannel chan UEMessage
	n2             atomic.Pointer[sctp.SCTPConn]
	terminated     atomic.Bool
	// lifecycle orders publishing a new association against Terminate and against
	// removing its AMF, so that either the dialler sees it is no longer wanted, or the
	// closer sees the association and closes it. This holds for each AMF, because
	// Terminate closes every AMF's association, not only the last one set as N2.
	lifecycle sync.Mutex
}

type PagedUE struct {
	FiveGSTMSI *ngapType.FiveGSTMSI
	Timestamp  time.Time
}

func (gnb *GNBContext) NewRanGnbContext(gnbId, mcc, mnc, tac, sst, sd string, n2, n3 netip.AddrPort) {
	gnb.controlInfo.mcc = mcc
	gnb.controlInfo.mnc = mnc
	gnb.controlInfo.tac = tac
	gnb.controlInfo.gnbId = gnbId
	gnb.controlInfo.identity, _ = config.ParseGNBIdentity(gnbId, 0, 0)
	gnb.controlInfo.inboundChannel = make(chan UEMessage, 100)
	gnb.sliceInfo.sd = sd
	gnb.sliceInfo.sst = sst
	gnb.controlInfo.gnbIpPort = n2
	gnb.ueIpGenerator = 3
	gnb.dataInfo.gnbIpPort = n3
}

func (gnb *GNBContext) NewGnBUe(gnbTx chan UEMessage, gnbRx chan UEMessage, prUeId int64, tmsi *nasType.MobileId5GS, connectionLost ...chan struct{}) (*GNBUe, error) {

	// TODO if necessary add more information for UE.

	// new instance of ue.
	ue := &GNBUe{}

	// set ran UE Ngap Id.
	ranId := gnb.getRanUeId()
	ue.SetRanUeId(ranId)

	// Connect gNB and UE's channels
	ue.SetGnbRx(gnbRx)
	ue.SetGnbTx(gnbTx)
	if len(connectionLost) != 0 {
		ue.SetConnectionLost(connectionLost[0])
	}
	ue.SetPrUeId(prUeId)
	ue.SetTMSI(tmsi)

	// set state to UE.
	ue.SetStateInitialized()

	// select AMF with Capacity is more than 0. Done before the UE is stored, so that a UE
	// arriving while no association is up is not left behind in the pools.
	amf := gnb.selectAmFByActive()
	if amf == nil {
		return nil, errors.New("no AMF available for this UE")
	}

	// set amfId and SCTP association for UE.
	ue.SetAmfId(amf.GetAmfId())
	ue.SetSCTP(amf.GetSCTPConn())

	// store UE in the UE Pool of GNB.
	gnb.uePool.Store(ranId, ue)
	if prUeId != 0 {
		gnb.prUePool.Store(prUeId, ue)
	}

	// return UE Context.
	return ue, nil
}

func (gnb *GNBContext) GetInboundChannel() chan UEMessage {
	return gnb.controlInfo.inboundChannel
}

func (gnb *GNBContext) GetN3GnbIp() netip.Addr {
	return gnb.dataInfo.gnbIpPort.Addr()
}

// SetGtpDevice gives this gNB the GTP-U device its UEs' tunnels share. The gNB owns
// it: it is closed when the gNB terminates. It is set after the NGAP receiver has
// started, and read from there, hence atomic.
func (gnb *GNBContext) SetGtpDevice(dev *gtp.Device) {
	gnb.gtpDevice.Store(dev)
}

// GetGtpDevice returns the GTP-U device this gNB's UEs share, or nil when each UE
// has its own or there are no tunnels.
func (gnb *GNBContext) GetGtpDevice() *gtp.Device {
	return gnb.gtpDevice.Load()
}

// CloseGtpDevice waits for this gNB's UEs to give back what they hold on its shared
// GTP-U device, then removes the device. Their policy rules and routes are host-wide
// and outlive the process, so the gNB lets them go first. The wait ends once stall
// passes with no UE releasing, or after limit.
func (gnb *GNBContext) CloseGtpDevice(stall, limit time.Duration) {
	dev := gnb.GetGtpDevice()
	if dev == nil {
		return
	}

	log.Info("[GNB][GTP] Waiting up to ", limit, " for UEs to release their tunnels on ", dev.Name())
	if held := dev.WaitIdle(stall, limit); held > 0 {
		log.Warn("[GNB][GTP] Removing shared GTP-U device ", dev.Name(), " while ", held, " UEs still hold rules on it")
	}

	dev.Close()
	log.Info("[GNB][GTP] Shared GTP-U device ", dev.Name(), " removed")
}

func (gnb *GNBContext) GetUePool() *sync.Map {
	return &gnb.uePool
}

func (gnb *GNBContext) GetPrUePool() *sync.Map {
	return &gnb.prUePool
}

func (gnb *GNBContext) DeleteGnBUe(ue *GNBUe) {
	gnb.uePool.Delete(ue.ranUeNgapId)
	gnb.prUePool.CompareAndDelete(ue.GetPrUeId(), ue)
	for _, pduSession := range ue.GetPduSessions() {
		if pduSession != nil {
			gnb.teidPool.Delete(pduSession.GetTeidDownlink())
		}
	}
	ue.CloseUEChannel()
}

func (gnb *GNBContext) GetGnbUe(ranUeId int64) (*GNBUe, error) {
	ue, err := gnb.uePool.Load(ranUeId)
	if !err {
		return nil, fmt.Errorf("UE is not find in GNB UE POOL")
	}
	gnbUe, ok := ue.(*GNBUe)
	if !ok || gnbUe == nil {
		return nil, fmt.Errorf("UE is nil or invalid type in GNB UE POOL")
	}
	return gnbUe, nil
}

func (gnb *GNBContext) GetGnbUeByAmfUeId(amfUeId int64) (*GNBUe, error) {
	var found *GNBUe
	gnb.uePool.Range(func(key, value any) bool {
		ue := value.(*GNBUe)
		if ue.HasAmfUeId() && ue.GetAmfUeId() == amfUeId {
			found = ue
			return false
		}
		return true
	})
	if found == nil {
		return nil, fmt.Errorf("UE is not found in GNB UE POOL using AMF UE ID")
	}
	return found, nil
}

func (gnb *GNBContext) GetGnbUeByPrUeId(pRUeId int64) (*GNBUe, error) {
	ue, err := gnb.prUePool.Load(pRUeId)
	if !err {
		return nil, fmt.Errorf("UE is not find in GNB PR UE POOL")
	}
	gnbUe, ok := ue.(*GNBUe)
	if !ok || gnbUe == nil {
		return nil, fmt.Errorf("UE is nil or invalid type in GNB PR UE POOL")
	}
	return gnbUe, nil
}

func (gnb *GNBContext) GetGnbUeByTeid(teid uint32) (*GNBUe, error) {
	ue, err := gnb.teidPool.Load(teid)
	if !err {
		return nil, fmt.Errorf("UE is not find in GNB UE POOL using TEID")
	}
	gnbUe, ok := ue.(*GNBUe)
	if !ok || gnbUe == nil {
		return nil, fmt.Errorf("UE is nil or invalid type in GNB UE POOL using TEID")
	}
	return gnbUe, nil
}

func (gnb *GNBContext) NewGnBAmf(ipPort netip.AddrPort) *GNBAmf {

	// TODO if necessary add more information for AMF.

	amf := &GNBAmf{}

	// set id for AMF.
	amfId := gnb.getRanAmfId()
	amf.setAmfId(amfId)

	// set AMF ip and AMF port.
	amf.SetAmfIpPort(ipPort)

	// set state to AMF.
	amf.SetStateInactive()

	// store AMF in the AMF Pool of GNB.
	gnb.amfPool.Store(amfId, amf)

	// Plmns and slices supported by AMF initialized.
	amf.SetLenPlmns(0)
	amf.SetLenSlice(0)

	// return AMF Context
	return amf
}

func (gnb *GNBContext) IterGnbAmf() iter.Seq[*GNBAmf] {
	return func(yield func(*GNBAmf) bool) {
		gnb.amfPool.Range(func(key, value any) bool {
			return yield(value.(*GNBAmf))
		})
	}
}

func (gnb *GNBContext) FindGnbAmfByIpPort(ipPort netip.AddrPort) *GNBAmf {
	for amf := range gnb.IterGnbAmf() {
		if amf.GetAmfIpPort() == ipPort {
			return amf
		}
	}
	return nil
}

func (gnb *GNBContext) DeleteGnBAmf(amfId int64) {
	gnb.amfPool.Delete(amfId)
}

// RemoveGnbAmf stops serving through the AMF and closes its association, including one a
// re-establishment publishes concurrently.
func (gnb *GNBContext) RemoveGnbAmf(amf *GNBAmf) {
	gnb.controlInfo.lifecycle.Lock()
	gnb.DeleteGnBAmf(amf.GetAmfId())
	conn := amf.GetSCTPConn()
	gnb.controlInfo.lifecycle.Unlock()

	if conn != nil {
		_ = conn.Close()
	}
}

// PublishAssociation makes conn the AMF's association, unless the gNB has been terminated or
// no longer serves through the AMF; the caller then owns conn and must close it.
func (gnb *GNBContext) PublishAssociation(amf *GNBAmf, conn *sctp.SCTPConn) bool {
	gnb.controlInfo.lifecycle.Lock()
	defer gnb.controlInfo.lifecycle.Unlock()

	if gnb.IsTerminated() || !gnb.HasGnbAmf(amf.GetAmfId()) {
		return false
	}
	amf.SetSCTPConn(conn)
	gnb.SetN2(conn)
	return true
}

// HasGnbAmf reports whether the AMF is still one this gNB serves through, as opposed to
// one InitGnb abandoned or an AMF Configuration Update removed.
func (gnb *GNBContext) HasGnbAmf(amfId int64) bool {
	_, ok := gnb.amfPool.Load(amfId)
	return ok
}

func (gnb *GNBContext) selectAmFByActive() *GNBAmf {
	var amfSelect *GNBAmf
	var maxWeightFactor int64 = -1
	for amf := range gnb.IterGnbAmf() {
		if weight := amf.GetTNLAWeight(); amf.GetState() == Active && maxWeightFactor < weight {
			maxWeightFactor = weight
			amfSelect = amf
		}
	}
	return amfSelect
}

func (gnb *GNBContext) getRanUeId() int64 {
	return gnb.idUeGenerator.Add(1)
}

func (gnb *GNBContext) GetUeTeid(ue *GNBUe) uint32 {
	id := gnb.teidGenerator.Add(1)
	gnb.teidPool.Store(id, ue)
	return id
}

// for AMFs Pools.
func (gnb *GNBContext) getRanAmfId() int64 {
	return gnb.idAmfGenerator.Add(1)
}

func (gnb *GNBContext) SetN2(n2 *sctp.SCTPConn) {
	gnb.controlInfo.n2.Store(n2)
}

func (gnb *GNBContext) GetN2() *sctp.SCTPConn {
	return gnb.controlInfo.n2.Load()
}

// IsTerminated reports whether Terminate has been called, so that the loss of an association
// the gNB closed itself is not mistaken for one to re-establish.
func (gnb *GNBContext) IsTerminated() bool {
	return gnb.controlInfo.terminated.Load()
}

// ReleaseUesOfAmf deletes the context of every UE served through the given AMF and returns how
// many there were. A UE-associated logical NG-connection does not outlive its TNL association,
// so once the association is gone these contexts refer to nothing on the AMF side.
func (gnb *GNBContext) ReleaseUesOfAmf(amfId int64) int {
	released := 0
	gnb.uePool.Range(func(_, value any) bool {
		if ue, ok := value.(*GNBUe); ok && ue.GetAmfId() == amfId {
			ue.FailUEChannel()
			gnb.DeleteGnBUe(ue)
			released++
		}
		return true
	})
	return released
}

func (gnb *GNBContext) GetGnbId() string {
	return gnb.controlInfo.gnbId
}

func (gnb *GNBContext) GetGnbIpPort() netip.AddrPort {
	return gnb.controlInfo.gnbIpPort
}

// SetGnbIpPort sets the N2 and N3 addresses; InitGnb moves to the next ones on each retry.
func (gnb *GNBContext) SetGnbIpPort(n2, n3 netip.AddrPort) {
	gnb.controlInfo.gnbIpPort = n2
	gnb.dataInfo.gnbIpPort = n3
}

// SetInterfaces sets the N2 and N3 interfaces, with the IPv6 address of a dual-stack
// one and how N3 chooses between IP versions.
func (gnb *GNBContext) SetInterfaces(n2, n3 config.GnbInterface) {
	gnb.SetGnbIpPort(n2.AddrPort, n3.AddrPort)
	gnb.controlInfo.ipv6 = n2.IPv6
	gnb.dataInfo.ipv6 = n3.IPv6
	gnb.dataInfo.preferIPv6 = n3.PreferredFamily == config.IPv6
	gnb.dataInfo.advertiseAll = n3.Advertise == config.AdvertiseAll
}

// ControlInterface is the N2 interface of the gNB.
func (gnb *GNBContext) ControlInterface() config.GnbInterface {
	return config.GnbInterface{IPv4Port: config.IPv4Port{AddrPort: gnb.controlInfo.gnbIpPort}, IPv6: gnb.controlInfo.ipv6}
}

// DataInterface is the N3 interface of the gNB.
func (gnb *GNBContext) DataInterface() config.GnbInterface {
	n3 := config.GnbInterface{IPv4Port: config.IPv4Port{AddrPort: gnb.dataInfo.gnbIpPort}, IPv6: gnb.dataInfo.ipv6}
	if gnb.dataInfo.preferIPv6 {
		n3.PreferredFamily = config.IPv6
	}
	if gnb.dataInfo.advertiseAll {
		n3.Advertise = config.AdvertiseAll
	}
	return n3
}

// GetN2LocalFor returns the N2 address and port of the gNB of the IP version of the
// AMF address amf, from which to reach it.
func (gnb *GNBContext) GetN2LocalFor(amf netip.Addr) (netip.AddrPort, error) {
	n2 := gnb.ControlInterface()
	local, ok := n2.AddrOf(config.FamilyOf(amf))
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("the AMF address %s is %s, but gnodeb.controlif (%s) has no %s address",
			amf, config.FamilyOf(amf), n2, config.FamilyOf(amf))
	}
	return netip.AddrPortFrom(local, n2.Port()), nil
}

// GetN3LocalFor returns the N3 address of the gNB towards the UPF address upf: that
// of its IP version, or the gNB's only one if it has none of that version.
func (gnb *GNBContext) GetN3LocalFor(upf netip.Addr) netip.Addr {
	if upf.IsValid() {
		if local, ok := gnb.DataInterface().AddrOf(config.FamilyOf(upf)); ok {
			return local
		}
	}
	return gnb.GetN3GnbIp()
}

// GetN3LocalForSession is GetN3LocalFor the UPF of the PDU session, if any.
func (gnb *GNBContext) GetN3LocalForSession(pduSession *GnbPDUSession) netip.Addr {
	var upf netip.Addr
	if pduSession != nil {
		upf = pduSession.GetUpfAddr()
	}
	return gnb.GetN3LocalFor(upf)
}

// GetDownlinkAddrs returns what the gNB signals as its N3 address of a PDU session
// whose UPF is upf: its address of the IP version used towards that UPF, or with
// dataif.advertise "all" every address it has, which a dual-stack gNB signals in
// 160 bits (TS 38.414 §5.1).
func (gnb *GNBContext) GetDownlinkAddrs(upf netip.Addr) []netip.Addr {
	if gnb.dataInfo.advertiseAll {
		var addrs []netip.Addr
		for _, addr := range []netip.Addr{gnb.dataInfo.gnbIpPort.Addr(), gnb.dataInfo.ipv6} {
			if addr.IsValid() {
				addrs = append(addrs, addr)
			}
		}
		return addrs
	}
	return []netip.Addr{gnb.GetN3LocalFor(upf)}
}

// SelectUpfAddress returns the address of the UPF in its UL Transport Layer Address,
// which TS 38.414 §5.1 lets carry an IPv4 address, an IPv6 one or both. Of both it
// takes the one of dataif.preferredfamily, IPv4 by default, if the gNB has both IP
// versions on N3; otherwise the one of the version the gNB has. A UPF of no version
// the gNB has is still returned, with a warning: there may be no tunnel to set up.
func (gnb *GNBContext) SelectUpfAddress(address *ngapType.TransportLayerAddress) (netip.Addr, error) {
	v4, v6, err := ngapCodec.TransportAddresses(address)
	if err != nil {
		return netip.Addr{}, err
	}
	return selectUpfAddress(v4, v6, gnb.DataInterface()), nil
}

func selectUpfAddress(v4, v6 netip.Addr, n3 config.GnbInterface) netip.Addr {
	usable4, usable6 := v4.IsValid() && n3.HasIPv4(), v6.IsValid() && n3.HasIPv6()
	switch {
	case usable4 && usable6 && n3.PreferredFamily == config.IPv6:
		return v6
	case usable4:
		return v4
	case usable6:
		return v6
	}
	upf := v4
	if !upf.IsValid() {
		upf = v6
	}
	log.Warn("[GNB][NGAP] The UPF's N3 address ", upf, " is of an IP version gnodeb.dataif (", n3, ") does not have: GTP-U cannot reach it")
	return upf
}

func (gnb *GNBContext) AddPagedUE(tmsi *ngapType.FiveGSTMSI) {
	gnb.pagedUELock.Lock()
	defer gnb.pagedUELock.Unlock()

	pagedUE := PagedUE{
		FiveGSTMSI: tmsi,
		Timestamp:  time.Now(),
	}
	gnb.pagedUEs = append(gnb.pagedUEs, pagedUE)

	go func() {
		time.Sleep(time.Second)
		gnb.pagedUELock.Lock()
		i := slices.Index(gnb.pagedUEs, pagedUE)
		if i == -1 {
			return
		}
		gnb.pagedUEs = slices.Delete(gnb.pagedUEs, i, i)
		gnb.pagedUELock.Unlock()
	}()
}

func (gnb *GNBContext) GetPagedUEs() []PagedUE {
	gnb.pagedUELock.Lock()
	defer gnb.pagedUELock.Unlock()

	return gnb.pagedUEs[:]
}

func (gnb *GNBContext) GetGnbIdInBytes() []byte {
	return gnb.controlInfo.identity.Bytes()
}

// ConfigureIdentity sets the gNB ID width and cell suffix; the default is 24 bits and cell 0.
func (gnb *GNBContext) ConfigureIdentity(bits uint8, cell uint16) error {
	id, err := config.ParseGNBIdentity(gnb.controlInfo.gnbId, bits, cell)
	if err != nil {
		return err
	}
	gnb.controlInfo.identity = id
	return nil
}

func (gnb *GNBContext) GetGNBIDBitString() aper.BitString {
	id := gnb.controlInfo.identity
	return aper.BitString{Bytes: id.Bytes(), BitLength: uint64(id.BitLength)}
}

func (gnb *GNBContext) GetTacInBytes() []byte {
	// changed for bytes.
	resu, err := hex.DecodeString(gnb.controlInfo.tac)
	if err != nil {
		fmt.Println(err)
	}
	return resu
}

func (gnb *GNBContext) GetSliceInBytes() ([]byte, []byte) {
	sstBytes, err := hex.DecodeString(gnb.sliceInfo.sst)
	if err != nil {
		fmt.Println(err)
	}

	if gnb.sliceInfo.sd != "" {
		sdBytes, err := hex.DecodeString(gnb.sliceInfo.sd)
		if err != nil {
			fmt.Println(err)
		}
		return sstBytes, sdBytes
	}
	return sstBytes, nil
}

func (gnb *GNBContext) GetPLMNIdentity() *ngapType.PLMNIdentity {
	return &ngapType.PLMNIdentity{Value: gnb.GetMccAndMncInOctets()}
}

func (gnb *GNBContext) GetNRCellIdentity() *ngapType.NRCellIdentity {
	return &ngapType.NRCellIdentity{
		Value: aper.BitString{
			Bytes:     gnb.controlInfo.identity.CellBytes(),
			BitLength: 36,
		},
	}
}

func (gnb *GNBContext) GetMccAndMnc() (string, string) {
	return gnb.controlInfo.mcc, gnb.controlInfo.mnc
}

func (gnb *GNBContext) GetMccAndMncInOctets() []byte {
	mcc, mnc := gnb.GetMccAndMnc()
	encoded, err := ngapCodec.EncodePLMN(mcc, mnc)
	if err != nil {
		log.Errorf("[GNB] Could not encode PLMN: %v", err)
		return nil
	}
	return encoded
}

func (gnb *GNBContext) Terminate() {
	gnb.controlInfo.lifecycle.Lock()
	gnb.controlInfo.terminated.Store(true)
	// N2 is also the conn of the AMF that published it; collect each conn once.
	conns := []*sctp.SCTPConn{gnb.GetN2()}
	for amf := range gnb.IterGnbAmf() {
		if conn := amf.GetSCTPConn(); !slices.Contains(conns, conn) {
			conns = append(conns, conn)
		}
	}
	gnb.controlInfo.lifecycle.Unlock()

	// close all connections
	close(gnb.GetInboundChannel())
	log.Info("[GNB][UE] NAS channel Terminated")

	for _, conn := range conns {
		if conn != nil {
			log.Info("[GNB][AMF] N2/TNLA Terminated")
			conn.Close()
		}
	}

	gnb.CloseGtpDevice(0, 0)

	log.Info("GNB Terminated")
}
