/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2026 Balázs Toldi
 */
package context

import (
	"net/netip"
	"testing"

	"my5G-RANTester/config"
	ngapCodec "my5G-RANTester/lib/ngap"

	"github.com/stretchr/testify/require"
)

var (
	n3v4, n3v6   = netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("2001:db8:630::10")
	upfV4, upfV6 = netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8:630::1")
)

func gnbInterface(port uint16, addrs ...netip.Addr) config.GnbInterface {
	n := config.GnbInterface{IPv4Port: config.IPv4Port{AddrPort: netip.AddrPortFrom(addrs[0], port)}}
	if len(addrs) == 2 {
		n.IPv6 = addrs[1]
	}
	return n
}

func dualStackGnb(n2, n3 config.GnbInterface) *GNBContext {
	gnb := &GNBContext{}
	gnb.NewRanGnbContext("000008", "001", "01", "000001", "1", "000001", n2.AddrPort, n3.AddrPort)
	gnb.SetInterfaces(n2, n3)
	return gnb
}

// The UPF's address is of an IP version the gNB has on N3: of both, IPv4 unless
// dataif.preferredfamily is ipv6.
func TestSelectUpfAddress(t *testing.T) {
	for _, tc := range []struct {
		name   string
		n3     []netip.Addr
		prefer config.IPFamily
		upf    []netip.Addr
		want   netip.Addr
	}{
		{"IPv4 gNB, IPv4 UPF", []netip.Addr{n3v4}, "", []netip.Addr{upfV4}, upfV4},
		{"IPv6 gNB, IPv6 UPF", []netip.Addr{n3v6}, "", []netip.Addr{upfV6}, upfV6},
		{"IPv4 gNB, dual-stack UPF", []netip.Addr{n3v4}, config.IPv6, []netip.Addr{upfV4, upfV6}, upfV4},
		{"IPv6 gNB, dual-stack UPF", []netip.Addr{n3v6}, config.IPv4, []netip.Addr{upfV4, upfV6}, upfV6},
		{"dual-stack, dual-stack UPF", []netip.Addr{n3v4, n3v6}, "", []netip.Addr{upfV4, upfV6}, upfV4},
		{"dual-stack, dual-stack UPF, IPv4 preferred", []netip.Addr{n3v4, n3v6}, config.IPv4, []netip.Addr{upfV4, upfV6}, upfV4},
		{"dual-stack, dual-stack UPF, IPv6 preferred", []netip.Addr{n3v4, n3v6}, config.IPv6, []netip.Addr{upfV4, upfV6}, upfV6},
		{"dual-stack, IPv4 UPF, IPv6 preferred", []netip.Addr{n3v4, n3v6}, config.IPv6, []netip.Addr{upfV4}, upfV4},
		{"dual-stack, IPv6 UPF", []netip.Addr{n3v4, n3v6}, "", []netip.Addr{upfV6}, upfV6},
		// No GTP-U path, but signalling-only tests go on, as before.
		{"IPv4 gNB, IPv6 UPF", []netip.Addr{n3v4}, "", []netip.Addr{upfV6}, upfV6},
		{"IPv6 gNB, IPv4 UPF", []netip.Addr{n3v6}, "", []netip.Addr{upfV4}, upfV4},
	} {
		n3 := gnbInterface(2152, tc.n3...)
		n3.PreferredFamily = tc.prefer
		gnb := dualStackGnb(gnbInterface(9487, n3v4), n3)
		address, err := ngapCodec.TransportLayerAddress(tc.upf...)
		require.NoError(t, err)
		got, err := gnb.SelectUpfAddress(address)
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.want, got, tc.name)
	}
	_, err := dualStackGnb(gnbInterface(9487, n3v4), gnbInterface(2152, n3v4)).SelectUpfAddress(nil)
	require.Error(t, err)
}

func TestN3LocalAndDownlinkAddrs(t *testing.T) {
	dual := gnbInterface(2152, n3v4, n3v6)
	gnb := dualStackGnb(gnbInterface(9487, n3v4), dual)
	require.Equal(t, n3v4, gnb.GetN3LocalFor(upfV4))
	require.Equal(t, n3v6, gnb.GetN3LocalFor(upfV6))
	require.Equal(t, n3v4, gnb.GetN3LocalFor(netip.Addr{}), "without a UPF: the address in ip")
	require.Equal(t, n3v4, gnb.GetN3GnbIp(), "unchanged: the address in ip")
	require.Equal(t, []netip.Addr{n3v6}, gnb.GetDownlinkAddrs(upfV6))
	require.Equal(t, []netip.Addr{n3v4}, gnb.GetDownlinkAddrs(upfV4))
	require.Equal(t, n3v6, gnb.GetN3LocalForSession(&GnbPDUSession{upfIp: upfV6.String()}))
	require.Equal(t, n3v4, gnb.GetN3LocalForSession(nil))

	dual.Advertise = config.AdvertiseAll
	gnb = dualStackGnb(gnbInterface(9487, n3v4), dual)
	require.Equal(t, []netip.Addr{n3v4, n3v6}, gnb.GetDownlinkAddrs(upfV6), "160 bits")
	require.Equal(t, dual, gnb.DataInterface())

	only6 := dualStackGnb(gnbInterface(9487, n3v6), gnbInterface(2152, n3v6))
	require.Equal(t, n3v6, only6.GetN3LocalFor(upfV4), "of no matching IP version: the gNB's only one")
	require.Equal(t, []netip.Addr{n3v6}, only6.GetDownlinkAddrs(upfV4))
}

func TestN2LocalFor(t *testing.T) {
	n2v4, n2v6 := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8:620::10")
	amfV4, amfV6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8:620::1")

	dual := dualStackGnb(gnbInterface(9487, n2v4, n2v6), gnbInterface(2152, n3v4))
	local, err := dual.GetN2LocalFor(amfV4)
	require.NoError(t, err)
	require.Equal(t, netip.AddrPortFrom(n2v4, 9487), local)
	local, err = dual.GetN2LocalFor(amfV6)
	require.NoError(t, err)
	require.Equal(t, netip.AddrPortFrom(n2v6, 9487), local)
	require.Equal(t, gnbInterface(9487, n2v4, n2v6), dual.ControlInterface())

	only4 := dualStackGnb(gnbInterface(9487, n2v4), gnbInterface(2152, n3v4))
	_, err = only4.GetN2LocalFor(amfV6)
	require.ErrorContains(t, err, "has no ipv6 address")
	only6 := dualStackGnb(gnbInterface(9487, n2v6), gnbInterface(2152, n3v6))
	_, err = only6.GetN2LocalFor(amfV4)
	require.ErrorContains(t, err, "has no ipv4 address")
	local, err = only6.GetN2LocalFor(amfV6)
	require.NoError(t, err)
	require.Equal(t, netip.AddrPortFrom(n2v6, 9487), local)
}
