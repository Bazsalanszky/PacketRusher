/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2026 Balázs Toldi
 */

package test

import (
	"my5G-RANTester/config"
	"my5G-RANTester/internal/analytics"
	"my5G-RANTester/internal/common/tools"
	gnbContext "my5G-RANTester/internal/control_test_engine/gnb/context"
	"my5G-RANTester/internal/control_test_engine/procedures"
	codec "my5G-RANTester/lib/ngap"
	"my5G-RANTester/test/aio5gc"
	"my5G-RANTester/test/aio5gc/context"
	amfTools "my5G-RANTester/test/aio5gc/lib/tools"
	"net/netip"
	"sync"
	"testing"
	"time"

	ngapType "github.com/free5gc/ngap/ie"
	"github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
	"github.com/stretchr/testify/require"
)

// TestIPv6Transport runs a UE's registration and PDU session over N2 and N3
// addresses of either IP version, against the mock core: over SCTP on ::1 for an
// IPv6 AMF, and with the UPF signalling an IPv4, an IPv6 or both N3 addresses. It
// checks the gNB's own N3 address in its PDU Session Resource Setup Response.
func TestIPv6Transport(t *testing.T) {
	v4, v6 := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")
	both := []netip.Addr{v4, v6}
	for i, tc := range []struct {
		name      string
		n2, n3    []netip.Addr // the gNB's addresses: IPv4 first in a dual-stack one
		amf       netip.Addr
		upf       []netip.Addr // what the core signals
		prefer    config.IPFamily
		advertise config.N3Advertise
		wantUpf   netip.Addr   // the UPF address the gNB selects
		wantDL    []netip.Addr // the gNB's N3 address it signals
	}{
		{name: "IPv6 only", n2: []netip.Addr{v6}, n3: []netip.Addr{v6}, amf: v6, upf: []netip.Addr{v6},
			wantUpf: v6, wantDL: []netip.Addr{v6}},
		{name: "IPv6 N2, IPv4 N3", n2: []netip.Addr{v6}, n3: []netip.Addr{v4}, amf: v6, upf: []netip.Addr{v4},
			wantUpf: v4, wantDL: []netip.Addr{v4}},
		{name: "dual-stack N2 to an IPv6 AMF", n2: both, n3: []netip.Addr{v4}, amf: v6, upf: []netip.Addr{v4},
			wantUpf: v4, wantDL: []netip.Addr{v4}},
		{name: "dual-stack, dual-stack UPF", n2: both, n3: both, amf: v4, upf: both,
			wantUpf: v4, wantDL: []netip.Addr{v4}},
		{name: "dual-stack, dual-stack UPF, IPv6 preferred", n2: []netip.Addr{v4}, n3: both, amf: v4, upf: both, prefer: config.IPv6,
			wantUpf: v6, wantDL: []netip.Addr{v6}},
		{name: "dual-stack, IPv6 UPF", n2: []netip.Addr{v4}, n3: both, amf: v4, upf: []netip.Addr{v6},
			wantUpf: v6, wantDL: []netip.Addr{v6}},
		{name: "dual-stack, every address advertised", n2: []netip.Addr{v4}, n3: both, amf: v4, upf: []netip.Addr{v6}, advertise: config.AdvertiseAll,
			wantUpf: v6, wantDL: both},
		{name: "IPv4 gNB, dual-stack UPF", n2: []netip.Addr{v4}, n3: []netip.Addr{v4}, amf: v4, upf: both, prefer: config.IPv6,
			wantUpf: v4, wantDL: []netip.Addr{v4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := analytics.Results()
			gnbInterface := func(addrs []netip.Addr, port uint16) config.GnbInterface {
				n := config.GnbInterface{IPv4Port: config.IPv4Port{AddrPort: netip.AddrPortFrom(addrs[0], port)}}
				if len(addrs) == 2 {
					n.IPv6 = addrs[1]
				}
				return n
			}
			amfs := []*config.AMF{{IPv4Port: config.IPv4Port{AddrPort: netip.AddrPortFrom(tc.amf, uint16(38640+i))}}}
			conf := amfTools.GenerateDefaultConf(netip.AddrPort{}, netip.AddrPort{}, amfs)
			conf.GNodeB.ControlIF = gnbInterface(tc.n2, uint16(29640+i))
			conf.GNodeB.DataIF = gnbInterface(tc.n3, 2152)
			conf.GNodeB.DataIF.PreferredFamily, conf.GNodeB.DataIF.Advertise = tc.prefer, tc.advertise
			require.NoError(t, conf.GNodeB.ControlIF.Validate())
			require.NoError(t, conf.GNodeB.DataIF.Validate())

			var mu sync.Mutex
			var downlinks []*ngapType.TransportLayerAddress
			fiveGC, err := (&aio5gc.FiveGCBuilder{}).WithConfig(conf).
				WithNGAPDispatcherHook(func(msg message.Message, _ *context.GNBContext, _ *context.Aio5gc) (bool, error) {
					response, ok := msg.(*message.PDUSessionResourceSetupResponse)
					if !ok || response.PDUSessionResourceSetupListSURes == nil {
						return false, nil
					}
					for _, item := range response.PDUSessionResourceSetupListSURes.List {
						transfer := &ngapType.PDUSessionResourceSetupResponseTransfer{}
						if err := codec.Unmarshal(item.PDUSessionResourceSetupResponseTransfer, transfer); err != nil {
							return false, err
						}
						tunnel, err := codec.Tunnel(transfer.DLQosFlowPerTNLInformation.UPTransportLayerInformation)
						if err != nil {
							return false, err
						}
						mu.Lock()
						downlinks = append(downlinks, tunnel.TransportLayerAddress)
						mu.Unlock()
					}
					return false, nil
				}).Build()
			require.NoError(t, err)
			t.Cleanup(func() { _ = fiveGC.Close() })
			fiveGC.GetSessionContext().SetN3(tc.upf...)

			wg := sync.WaitGroup{}
			gnbs, err := tools.CreateGnbs(t.Context(), 1, conf, &wg)
			require.NoError(t, err)
			t.Cleanup(func() {
				for _, gnb := range gnbs {
					gnb.Terminate()
				}
			})

			simConfig := tools.UESimulationConfig{Gnbs: gnbs, Cfg: conf, NumPduSessions: 1, UeId: 1}
			securityContext := context.SecurityContext{}
			securityContext.SetMsin(tools.IncrementMsin(simConfig.UeId, conf.Ue.Msin))
			securityContext.SetAuthSubscription(conf.Ue.Key, conf.Ue.Opc, "c9e8763286b5b9ffbdf56e1297d0887b", conf.Ue.Amf, conf.Ue.Sqn)
			securityContext.SetAbba([]uint8{0x00, 0x00})
			err = fiveGC.GetAMFContext().Provision(models.Snssai{Sst: int32(conf.Ue.Snssai.Sst), Sd: conf.Ue.Snssai.Sd}, securityContext)
			require.NoError(t, err)
			simulations := []*tools.UESimulation{tools.SimulateSingleUE(simConfig, &wg)}
			t.Cleanup(func() { stopTestSimulations(t, simulations) })

			require.Eventually(t, func() bool {
				return analytics.Results()[analytics.SessionEstablishment].Success-before[analytics.SessionEstablishment].Success == 1
			}, 15*time.Second, 10*time.Millisecond, "the UE must accept its PDU session")

			mu.Lock()
			require.Len(t, downlinks, 1)
			want, err := codec.TransportLayerAddress(tc.wantDL...)
			require.NoError(t, err)
			require.Equal(t, want.Value, downlinks[0].Value, "the gNB's N3 address")
			mu.Unlock()

			for _, gnb := range gnbs {
				sessions := 0
				gnb.GetUePool().Range(func(_, value any) bool {
					for _, session := range value.(*gnbContext.GNBUe).GetPduSessions() {
						if session != nil {
							sessions++
							require.Equal(t, tc.wantUpf, session.GetUpfAddr(), "the UPF address")
							require.Equal(t, tc.wantUpf.Is4(), gnb.GetN3LocalForSession(session).Is4(), "the gNB's N3 address towards it")
						}
					}
					return true
				})
				require.Equal(t, 1, sessions)
			}
			require.True(t, simulations[0].Send(procedures.UeTesterMessage{Type: procedures.Terminate}))
			waitTestSimulations(t, simulations, 15*time.Second)
		})
	}
}
