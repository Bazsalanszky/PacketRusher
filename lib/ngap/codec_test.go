/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2026 Balázs Toldi
 */
package ngap

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/free5gc/ngap/aper"
	"github.com/free5gc/ngap/ie"
	"github.com/stretchr/testify/require"
)

var (
	testV4     = netip.MustParseAddr("192.0.2.1")
	testV6     = netip.MustParseAddr("2001:db8:630::1")
	testV4Wire = []byte{192, 0, 2, 1}
	testV6Wire = testV6.AsSlice()
)

func address(bits uint64, data ...[]byte) *ie.TransportLayerAddress {
	return &ie.TransportLayerAddress{Value: aper.BitString{Bytes: bytes.Join(data, nil), BitLength: bits}}
}

// TS 38.414 §5.1: 32 bits of IPv4, 128 of IPv6, or 160 with IPv4 first. Anything
// else, including a byte count that does not match the bit count, is an error and
// never a panic.
func TestTransportAddresses(t *testing.T) {
	for _, tc := range []struct {
		name     string
		address  *ie.TransportLayerAddress
		v4, v6   netip.Addr
		rejected bool
	}{
		{name: "IPv4", address: address(32, testV4Wire), v4: testV4},
		{name: "IPv6", address: address(128, testV6Wire), v6: testV6},
		{name: "both", address: address(160, testV4Wire, testV6Wire), v4: testV4, v6: testV6},
		{name: "IPv4-mapped in 128 bits", address: address(128, netip.AddrFrom16(testV4.As16()).AsSlice()), v4: testV4},
		{name: "missing", address: nil, rejected: true},
		{name: "empty", address: address(0), rejected: true},
		{name: "32 bits in 3 bytes", address: address(32, testV4Wire[:3]), rejected: true},
		{name: "32 bits in 16 bytes", address: address(32, testV6Wire), rejected: true},
		{name: "128 bits in 4 bytes", address: address(128, testV4Wire), rejected: true},
		{name: "128 bits in 20 bytes", address: address(128, testV4Wire, testV6Wire), rejected: true},
		{name: "160 bits in 16 bytes", address: address(160, testV6Wire), rejected: true},
		{name: "160 bits in 21 bytes", address: address(160, testV4Wire, testV6Wire, []byte{0}), rejected: true},
		{name: "160 bits without bytes", address: address(160), rejected: true},
		{name: "64 bits", address: address(64, testV4Wire, testV4Wire), rejected: true},
		{name: "24 bits", address: address(24, testV4Wire[:3]), rejected: true},
		{name: "IPv4-mapped IPv6 half of 160 bits", address: address(160, testV4Wire, netip.AddrFrom16(testV4.As16()).AsSlice()), rejected: true},
		{name: "unspecified IPv4", address: address(32, make([]byte, 4)), rejected: true},
		{name: "unspecified IPv6", address: address(128, make([]byte, 16)), rejected: true},
		{name: "unspecified IPv6 half", address: address(160, testV4Wire, make([]byte, 16)), rejected: true},
	} {
		v4, v6, err := TransportAddresses(tc.address)
		if tc.rejected {
			require.Error(t, err, tc.name)
			require.False(t, v4.IsValid() || v6.IsValid(), tc.name)
			continue
		}
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.v4, v4, tc.name)
		require.Equal(t, tc.v6, v6, tc.name)
	}
}

func TestTransportLayerAddress(t *testing.T) {
	for _, tc := range []struct {
		name  string
		addrs []netip.Addr
		want  *ie.TransportLayerAddress // nil: rejected
	}{
		{"IPv4", []netip.Addr{testV4}, address(32, testV4Wire)},
		{"IPv6", []netip.Addr{testV6}, address(128, testV6Wire)},
		{"both", []netip.Addr{testV4, testV6}, address(160, testV4Wire, testV6Wire)},
		{"both, IPv6 first", []netip.Addr{testV6, testV4}, address(160, testV4Wire, testV6Wire)},
		{"IPv4-mapped", []netip.Addr{netip.AddrFrom16(testV4.As16())}, address(32, testV4Wire)},
		{"zoned IPv6", []netip.Addr{netip.MustParseAddr("fe80::1%eth0")}, address(128, netip.MustParseAddr("fe80::1").AsSlice())},
		{"none", nil, nil},
		{"invalid", []netip.Addr{{}}, nil},
		{"unspecified", []netip.Addr{netip.IPv4Unspecified()}, nil},
		{"two IPv4", []netip.Addr{testV4, testV4.Next()}, nil},
		{"two IPv6", []netip.Addr{testV6, testV6.Next()}, nil},
		{"three", []netip.Addr{testV4, testV6, testV4.Next()}, nil},
	} {
		got, err := TransportLayerAddress(tc.addrs...)
		if tc.want == nil {
			require.Error(t, err, tc.name)
			continue
		}
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.want, got, tc.name)
	}
}

func TestIPAddressConversions(t *testing.T) {
	for _, tc := range []struct{ name, v4, v6 string }{
		{"IPv4", "192.0.2.1", ""},
		{"IPv6", "", "2001:db8::1"},
		{"both", "192.0.2.1", "2001:db8::1"},
	} {
		encoded := IPAddressToNgap(tc.v4, tc.v6)
		require.NotNil(t, encoded, tc.name)
		v4, v6 := IPAddressToString(encoded)
		require.Equal(t, tc.v4, v4, tc.name)
		require.Equal(t, tc.v6, v6, tc.name)
	}
	// The single address may be of either version, as before.
	require.Equal(t, address(128, testV6Wire), IPAddressToNgap(testV6.String(), ""))
	for _, bad := range [][2]string{{"192.0.2", ""}, {"", "2001:db8::g"}, {"2001:db8::1", "192.0.2.1"}, {"192.0.2.1", "192.0.2.2"}} {
		require.Nil(t, IPAddressToNgap(bad[0], bad[1]), bad)
	}
	for _, malformed := range []*ie.TransportLayerAddress{nil, address(160, testV6Wire), address(64, testV4Wire, testV4Wire)} {
		v4, v6 := IPAddressToString(malformed)
		require.Empty(t, v4+v6)
	}
}

// Each form survives APER encoding in a GTP tunnel, as in a PDU Session Resource
// Setup Response Transfer.
func TestGTPTunnelAperRoundTrip(t *testing.T) {
	for _, addrs := range [][]netip.Addr{{testV4}, {testV6}, {testV4, testV6}} {
		transfer := ie.PDUSessionResourceSetupResponseTransfer{DLQosFlowPerTNLInformation: &ie.QosFlowPerTNLInformation{
			UPTransportLayerInformation: GTPTunnel(7, addrs...),
			AssociatedQosFlowList:       &ie.AssociatedQosFlowList{List: []ie.AssociatedQosFlowItem{{QosFlowIdentifier: &ie.QosFlowIdentifier{Value: 1}}}},
		}}
		encoded, err := Marshal(&transfer)
		require.NoError(t, err, addrs)
		decoded := ie.PDUSessionResourceSetupResponseTransfer{}
		require.NoError(t, Unmarshal(encoded, &decoded), addrs)
		tunnel, err := Tunnel(decoded.DLQosFlowPerTNLInformation.UPTransportLayerInformation)
		require.NoError(t, err, addrs)
		v4, v6, err := TransportAddresses(tunnel.TransportLayerAddress)
		require.NoError(t, err, addrs)
		var got []netip.Addr
		for _, addr := range []netip.Addr{v4, v6} {
			if addr.IsValid() {
				got = append(got, addr)
			}
		}
		require.Equal(t, addrs, got)
		require.Equal(t, []byte{0, 0, 0, 7}, []byte(tunnel.GTPTEID.Value))
	}
	// An invalid address is not encoded as an empty one, which the peer would misread.
	_, err := Marshal(&ie.PathSwitchRequestTransfer{
		DLNGUUPTNLInformation: GTPTunnel(7, netip.Addr{}),
		QosFlowAcceptedList:   &ie.QosFlowAcceptedList{List: []ie.QosFlowAcceptedItem{{QosFlowIdentifier: &ie.QosFlowIdentifier{Value: 1}}}},
	})
	require.Error(t, err)
}
