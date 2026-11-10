/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2026 Balázs Toldi
 */
package ngap

import (
	"net"
	"net/netip"
	"testing"

	"my5G-RANTester/config"
	"my5G-RANTester/internal/control_test_engine/gnb/context"
	ngapConvert "my5G-RANTester/lib/ngap"

	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	gnbV4, gnbV6 = netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("2001:db8:630::10")
	upfV4, upfV6 = netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8:630::1")
)

// withInterfaces gives the test gNB these N2 and N3 addresses, IPv4 first.
func withInterfaces(gnb *context.GNBContext, n2, n3 []netip.Addr, prefer config.IPFamily) *context.GNBContext {
	gnbInterface := func(port uint16, addrs []netip.Addr) config.GnbInterface {
		n := config.GnbInterface{IPv4Port: config.IPv4Port{AddrPort: netip.AddrPortFrom(addrs[0], port)}}
		if len(addrs) == 2 {
			n.IPv6 = addrs[1]
		}
		return n
	}
	n3IF := gnbInterface(2152, n3)
	n3IF.PreferredFamily = prefer
	gnb.SetInterfaces(gnbInterface(9487, n2), n3IF)
	return gnb
}

func TestSctpEndpoints(t *testing.T) {
	for _, tc := range []struct {
		local, remote string
		network       string // "": refused
		localIP       net.IP
		remoteIP      net.IP
	}{
		{"192.0.2.10:9487", "192.0.2.1:38412", "sctp4", net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.1")},
		{"[2001:db8:620::10]:9487", "[2001:db8:620::1]:38412", "sctp6", net.ParseIP("2001:db8:620::10"), net.ParseIP("2001:db8:620::1")},
		{"[::1]:9487", "[::1]:38412", "sctp6", net.IPv6loopback, net.IPv6loopback},
		{"[::ffff:192.0.2.10]:9487", "192.0.2.1:38412", "sctp4", net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.1")},
		{"192.0.2.10:9487", "[2001:db8:620::1]:38412", "", nil, nil},
		{"[2001:db8:620::10]:9487", "192.0.2.1:38412", "", nil, nil},
	} {
		network, loc, rem, err := sctpEndpoints(netip.MustParseAddrPort(tc.local), netip.MustParseAddrPort(tc.remote))
		if tc.network == "" {
			require.ErrorContains(t, err, "different IP versions", tc.local)
			continue
		}
		require.NoError(t, err, tc.local)
		require.Equal(t, tc.network, network, tc.local)
		require.Len(t, loc.IPAddrs, 1)
		require.Len(t, rem.IPAddrs, 1)
		assert.True(t, tc.localIP.Equal(loc.IPAddrs[0].IP), tc.local)
		assert.True(t, tc.remoteIP.Equal(rem.IPAddrs[0].IP), tc.remote)
		assert.Equal(t, 9487, loc.Port)
		assert.Equal(t, 38412, rem.Port)
	}
	// A link-local AMF keeps its zone.
	_, loc, rem, err := sctpEndpoints(netip.MustParseAddrPort("[fe80::2%lo]:9487"), netip.MustParseAddrPort("[fe80::1%lo]:38412"))
	require.NoError(t, err)
	assert.Equal(t, "lo", loc.IPAddrs[0].Zone)
	assert.Equal(t, "lo", rem.IPAddrs[0].Zone)
}

// The UL tunnel address of the UPF may be 32, 128 or 160 bits (TS 38.414 §5.1). The
// handler used to read the first 4 bytes of any length as IPv4, so an IPv6 UPF became
// a nonsense IPv4 address; and the UE was told the gNB's address in ip, whatever the
// UPF's IP version.
func TestHandlerPduSessionResourceSetupRequest_UpfAddress(t *testing.T) {
	for _, tc := range []struct {
		name     string
		n3       []netip.Addr
		prefer   config.IPFamily
		upf      *ngapType.TransportLayerAddress
		wantUpf  netip.Addr // invalid: the session is skipped
		wantGnb3 netip.Addr
	}{
		{"IPv4", []netip.Addr{gnbV4}, "", tla(upfV4), upfV4, gnbV4},
		{"IPv6", []netip.Addr{gnbV6}, "", tla(upfV6), upfV6, gnbV6},
		{"both, IPv4 gNB", []netip.Addr{gnbV4}, "", tla(upfV4, upfV6), upfV4, gnbV4},
		{"both, IPv6 gNB", []netip.Addr{gnbV6}, "", tla(upfV4, upfV6), upfV6, gnbV6},
		{"both, dual-stack gNB", []netip.Addr{gnbV4, gnbV6}, "", tla(upfV4, upfV6), upfV4, gnbV4},
		{"both, dual-stack gNB preferring IPv6", []netip.Addr{gnbV4, gnbV6}, config.IPv6, tla(upfV4, upfV6), upfV6, gnbV6},
		{"IPv6, dual-stack gNB", []netip.Addr{gnbV4, gnbV6}, "", tla(upfV6), upfV6, gnbV6},
		{"64 bits", []netip.Addr{gnbV4}, "", &ngapType.TransportLayerAddress{Value: aper.BitString{Bytes: make([]byte, 8), BitLength: 64}}, netip.Addr{}, netip.Addr{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gnb := withInterfaces(createTestGNBContext(), []netip.Addr{gnbV4}, tc.n3, tc.prefer)
			ue := createTestUE(gnb, 12345)
			ue.CreateUeContext("not informed", "", []string{"01"}, []string{"010203"}, nil)
			ul := ngapConvert.UPTransport(netip.Addr{}, 1)
			ul.Choice.(*ngapType.GTPTunnel).TransportLayerAddress = tc.upf

			HandlerPduSessionResourceSetupRequest(gnb, pduSessionResourceSetupRequestUL(t, ue, []byte{0x01}, []byte{0x01, 0x02, 0x03}, true, ul))

			pduSession, err := ue.GetPduSession(1)
			require.NoError(t, err)
			if !tc.wantUpf.IsValid() {
				assert.Nil(t, pduSession, "a malformed UPF address skips the session")
				assert.Empty(t, ue.GetGnbTx())
				return
			}
			require.NotNil(t, pduSession)
			assert.Equal(t, tc.wantUpf.String(), pduSession.GetUpfIp())
			require.Len(t, ue.GetGnbTx(), 1)
			assert.Equal(t, tc.wantGnb3, (<-ue.GetGnbTx()).GnbIp, "the gNB's N3 address the tunnel uses")
		})
	}
}

func tla(addrs ...netip.Addr) *ngapType.TransportLayerAddress {
	address, err := ngapConvert.TransportLayerAddress(addrs...)
	if err != nil {
		panic(err)
	}
	return address
}

// An AMF TNL association of an AMF Configuration Update may be IPv4, IPv6 or both; the
// handler used to ignore any AMF without an IPv4 address.
func TestAmfTNLAddress(t *testing.T) {
	amfV4, amfV6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8:620::1")
	n2v4, n2v6 := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8:620::10")
	cp := func(address *ngapType.TransportLayerAddress) *ngapType.CPTransportLayerInformation {
		return &ngapType.CPTransportLayerInformation{Choice: address}
	}
	for _, tc := range []struct {
		name    string
		n2      []netip.Addr
		address *ngapType.CPTransportLayerInformation
		want    netip.Addr // invalid: ignored
	}{
		{"IPv4", []netip.Addr{n2v4}, cp(tla(amfV4)), amfV4},
		{"IPv6 to an IPv4 gNB", []netip.Addr{n2v4}, cp(tla(amfV6)), netip.Addr{}},
		{"IPv6", []netip.Addr{n2v6}, cp(tla(amfV6)), amfV6},
		{"both to an IPv4 gNB", []netip.Addr{n2v4}, cp(tla(amfV4, amfV6)), amfV4},
		{"both to an IPv6 gNB", []netip.Addr{n2v6}, cp(tla(amfV4, amfV6)), amfV6},
		{"both to a dual-stack gNB", []netip.Addr{n2v4, n2v6}, cp(tla(amfV4, amfV6)), amfV4},
		{"IPv6 to a dual-stack gNB", []netip.Addr{n2v4, n2v6}, cp(tla(amfV6)), amfV6},
		{"malformed", []netip.Addr{n2v4}, cp(&ngapType.TransportLayerAddress{Value: aper.BitString{Bytes: []byte{1, 2, 3}, BitLength: 32}}), netip.Addr{}},
		{"missing", []netip.Addr{n2v4}, nil, netip.Addr{}},
	} {
		gnb := withInterfaces(createTestGNBContext(), tc.n2, []netip.Addr{gnbV4}, "")
		got, ok := amfTNLAddress(gnb, tc.address)
		require.Equal(t, tc.want.IsValid(), ok, tc.name)
		if ok {
			require.Equal(t, netip.AddrPortFrom(tc.want, 38412), got, tc.name)
		}
	}
}
