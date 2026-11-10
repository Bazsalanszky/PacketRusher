package ngap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/free5gc/ngap/aper"
	"github.com/free5gc/ngap/ie"
)

// Marshal and Unmarshal encode NGAP transfer IEs with the current APER API.
func Marshal(value interface{ Write(*aper.PerBitData) error }) ([]byte, error) {
	data := aper.NewPerBitData(nil)
	if err := value.Write(data); err != nil {
		return nil, err
	}
	return data.Bytes(), nil
}
func Unmarshal(payload any, value interface{ Read(*aper.PerBitData) error }) error {
	var data []byte
	switch encoded := payload.(type) {
	case []byte:
		data = encoded
	case aper.OctetString:
		data = encoded
	case *aper.OctetString:
		if encoded == nil {
			return fmt.Errorf("missing NGAP transfer")
		}
		data = *encoded
	default:
		return fmt.Errorf("unsupported NGAP transfer %T", payload)
	}
	return value.Read(aper.NewPerBitData(data))
}

// IPAddressToNgap encodes an IPv4 address, an IPv6 address or both, as
// TransportLayerAddress does. It returns nil if an address does not parse or is not
// of its version.
func IPAddressToNgap(ipv4, ipv6 string) *ie.TransportLayerAddress {
	var addrs []netip.Addr
	for _, text := range []string{ipv4, ipv6} {
		if text == "" {
			continue
		}
		addr, err := netip.ParseAddr(text)
		if err != nil {
			return nil
		}
		addrs = append(addrs, addr)
	}
	if len(addrs) == 2 && (!addrs[0].Unmap().Is4() || !addrs[1].Is6() || addrs[1].Is4In6()) {
		return nil // Each must be of its own IP version.
	}
	address, err := TransportLayerAddress(addrs...)
	if err != nil {
		return nil
	}
	return address
}

// IPAddressToString decodes a Transport Layer Address into its IPv4 and IPv6
// addresses, either of which is empty if it is absent; both are if it is malformed.
func IPAddressToString(address *ie.TransportLayerAddress) (string, string) {
	v4, v6, err := TransportAddresses(address)
	if err != nil {
		return "", ""
	}
	var ipv4, ipv6 string
	if v4.IsValid() {
		ipv4 = v4.String()
	}
	if v6.IsValid() {
		ipv6 = v6.String()
	}
	return ipv4, ipv6
}

// TransportLayerAddress encodes the addresses of a node as TS 38.414 §5.1 lays out a
// Transport Layer Address: 32 bits for an IPv4 address, 128 for an IPv6 one, and 160
// for both, the IPv4 address first. Their order in addrs does not matter; an
// IPv4-mapped IPv6 address counts as IPv4, and a zone is dropped.
func TransportLayerAddress(addrs ...netip.Addr) (*ie.TransportLayerAddress, error) {
	var v4, v6 netip.Addr
	for _, addr := range addrs {
		addr = addr.Unmap().WithZone("")
		switch {
		case !addr.IsValid() || addr.IsUnspecified():
			return nil, fmt.Errorf("invalid transport layer address %q", addr)
		case addr.Is4() && !v4.IsValid():
			v4 = addr
		case addr.Is6() && !v6.IsValid():
			v6 = addr
		default:
			return nil, fmt.Errorf("transport layer address with two addresses of the version of %s", addr)
		}
	}
	var encoded []byte
	if v4.IsValid() {
		encoded = v4.AsSlice()
	}
	if v6.IsValid() {
		encoded = append(encoded, v6.AsSlice()...)
	}
	if len(encoded) == 0 {
		return nil, errors.New("transport layer address without an address")
	}
	return &ie.TransportLayerAddress{Value: aper.BitString{Bytes: encoded, BitLength: uint64(len(encoded) * 8)}}, nil
}

// TransportAddresses decodes a Transport Layer Address (TS 38.414 §5.1) into its
// IPv4 address, its IPv6 address, or both: either is invalid if absent. It accepts
// only the 32, 128 and 160 bits of the specification, in as many bytes, and rejects
// unspecified addresses. An IPv4-mapped address in 128 bits counts as IPv4.
func TransportAddresses(address *ie.TransportLayerAddress) (v4, v6 netip.Addr, err error) {
	if address == nil {
		return v4, v6, errors.New("missing transport layer address")
	}
	data, bits := address.Value.Bytes, address.Value.BitLength
	if uint64(len(data))*8 != bits {
		return v4, v6, fmt.Errorf("transport layer address of %d bits in %d bytes", bits, len(data))
	}
	switch bits {
	case 32:
		v4 = netip.AddrFrom4([4]byte(data))
	case 128:
		v6 = netip.AddrFrom16([16]byte(data))
		if v6.Is4In6() {
			v4, v6 = v6.Unmap(), netip.Addr{}
		}
	case 160:
		v4, v6 = netip.AddrFrom4([4]byte(data[:4])), netip.AddrFrom16([16]byte(data[4:]))
		if v6.Is4In6() {
			return netip.Addr{}, netip.Addr{}, fmt.Errorf("transport layer address with an IPv4-mapped IPv6 address %s", v6)
		}
	default:
		return v4, v6, fmt.Errorf("transport layer address of %d bits: neither IPv4 (32), IPv6 (128) nor both (160)", bits)
	}
	if v4.IsUnspecified() || v6.IsUnspecified() {
		return netip.Addr{}, netip.Addr{}, errors.New("transport layer address with an unspecified address")
	}
	return v4, v6, nil
}

func Tunnel(value *ie.UPTransportLayerInformation) (*ie.GTPTunnel, error) {
	if value == nil {
		return nil, fmt.Errorf("missing UP transport information")
	}
	tunnel, ok := value.Choice.(*ie.GTPTunnel)
	if !ok || tunnel == nil || tunnel.GTPTEID == nil || len(tunnel.GTPTEID.Value) != 4 || tunnel.TransportLayerAddress == nil {
		return nil, fmt.Errorf("missing or invalid GTP tunnel")
	}
	return tunnel, nil
}

// UPTransport is the GTP tunnel of teid at the address ip, IPv4 or IPv6.
func UPTransport(ip netip.Addr, teid uint32) *ie.UPTransportLayerInformation {
	return GTPTunnel(teid, ip)
}

// GTPTunnel is the GTP tunnel of teid at addrs, an IPv4 address, an IPv6 one or
// both, as TransportLayerAddress encodes them. Invalid addresses leave the tunnel
// without an address, which its encoding then rejects: the codec would otherwise
// encode an empty one.
func GTPTunnel(teid uint32, addrs ...netip.Addr) *ie.UPTransportLayerInformation {
	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value, teid)
	address, _ := TransportLayerAddress(addrs...) // nil on error
	return &ie.UPTransportLayerInformation{Choice: &ie.GTPTunnel{
		TransportLayerAddress: address,
		GTPTEID:               &ie.GTPTEID{Value: value},
	}}
}
func UserLocation(plmn *ie.PLMNIdentity, cell *ie.NRCellIdentity, tac []byte) *ie.UserLocationInformation {
	return &ie.UserLocationInformation{Choice: &ie.UserLocationInformationNR{
		NRCGI: &ie.NRCGI{PLMNIdentity: plmn, NRCellIdentity: cell},
		TAI:   &ie.TAI{PLMNIdentity: plmn, TAC: &ie.TAC{Value: tac}},
	}}
}
func Slice(sst, sd []byte) *ie.SNSSAI {
	value := &ie.SNSSAI{SST: &ie.SST{Value: sst}}
	if len(sd) > 0 {
		value.SD = &ie.SD{Value: sd}
	}
	return value
}
func Octets(value []byte) *aper.OctetString {
	encoded := aper.OctetString(value)
	return &encoded
}
func CPAddress(value *ie.CPTransportLayerInformation) *ie.TransportLayerAddress {
	if value == nil {
		return nil
	}
	address, _ := value.Choice.(*ie.TransportLayerAddress)
	return address
}
