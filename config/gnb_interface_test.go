/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2026 Balázs Toldi
 */
package config

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/require"
)

func decodeInterface(t *testing.T, document string) (GnbInterface, error) {
	t.Helper()
	var v struct {
		IF GnbInterface `yaml:"if"`
	}
	err := yaml.NewDecoder(strings.NewReader("if:\n"+document), yaml.Strict()).Decode(&v)
	return v.IF, err
}

func TestGnbInterfaceYAML(t *testing.T) {
	v4, v6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8:620::1")
	for _, tc := range []struct {
		name     string
		document string
		want     GnbInterface
		err      string
	}{
		{name: "IPv4, as before", document: `  ip: "192.0.2.1"
  port: 9487`, want: GnbInterface{IPv4Port: IPv4Port{netip.AddrPortFrom(v4, 9487)}}},
		{name: "IPv6", document: `  ip: "2001:db8:620::1"
  port: 9487`, want: GnbInterface{IPv4Port: IPv4Port{netip.AddrPortFrom(v6, 9487)}}},
		{name: "IPv6 in brackets", document: `  ip: "[2001:db8:620::1]"
  port: 9487`, want: GnbInterface{IPv4Port: IPv4Port{netip.AddrPortFrom(v6, 9487)}}},
		{name: "IPv6 with a zone", document: `  ip: "fe80::1%lo"
  port: 9487`, want: GnbInterface{IPv4Port: IPv4Port{netip.AddrPortFrom(netip.MustParseAddr("fe80::1%lo"), 9487)}}},
		{name: "IPv4-mapped", document: `  ip: "::ffff:192.0.2.1"
  port: 9487`, want: GnbInterface{IPv4Port: IPv4Port{netip.AddrPortFrom(v4, 9487)}}},
		{name: "dual-stack", document: `  ip: "192.0.2.1"
  ipv6: "2001:db8:620::1"
  port: 2152
  preferredfamily: ipv6
  advertise: all`, want: GnbInterface{IPv4Port: IPv4Port{netip.AddrPortFrom(v4, 2152)}, IPv6: v6, PreferredFamily: IPv6, Advertise: AdvertiseAll}},
		{name: "ipv6 alone", document: `  ipv6: "2001:db8:620::1"
  port: 2152`, want: GnbInterface{IPv4Port: IPv4Port{netip.AddrPortFrom(v6, 2152)}}},
		{name: "no address", document: `  port: 2152`, err: "ip:"},
		{name: "two IPv6", document: `  ip: "2001:db8:620::2"
  ipv6: "2001:db8:620::1"`, err: "not an IPv4 address"},
		{name: "IPv4 in ipv6", document: `  ip: "192.0.2.1"
  ipv6: "192.0.2.2"`, err: "not an IPv6 address"},
		{name: "unparsable", document: `  ip: "192.0.2.256"`, err: "cannot resolve"},
		{name: "unclosed bracket", document: `  ip: "[2001:db8::1"`, err: "cannot parse"},
		{name: "address with a port", document: `  ip: "[2001:db8::1]:9487"`, err: "cannot parse"},
		{name: "unknown family", document: `  ip: "192.0.2.1"
  preferredfamily: ip6`, err: "preferredfamily"},
		{name: "unknown advertise", document: `  ip: "192.0.2.1"
  advertise: both`, err: "advertise"},
		{name: "unknown field", document: `  ip: "192.0.2.1"
  ipv4: "192.0.2.1"`, err: "unknown field"},
	} {
		got, err := decodeInterface(t, tc.document)
		if tc.err != "" {
			require.ErrorContains(t, err, tc.err, tc.name)
			continue
		}
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.want, got, tc.name)
	}
}

func TestAMFAddressYAML(t *testing.T) {
	var v struct {
		AMFs []*AMF `yaml:"amfif"`
	}
	document := `amfif:
  - ip: "192.0.2.10"
    port: 38412
  - ip: "2001:db8:620::10"
    port: 38412
  - ip: "[2001:db8:620::11]"
    port: 38413
`
	require.NoError(t, yaml.NewDecoder(strings.NewReader(document), yaml.Strict()).Decode(&v))
	var got []string
	for _, amf := range v.AMFs {
		got = append(got, amf.String())
	}
	// netip.AddrPort brackets IPv6, as net.JoinHostPort does: what SCTP resolves.
	require.Equal(t, []string{"192.0.2.10:38412", "[2001:db8:620::10]:38412", "[2001:db8:620::11]:38413"}, got)
}

func TestResolveAddr(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ host, network, want, err string }{
		{"192.0.2.1", "", "192.0.2.1", ""},
		{"2001:db8::1", "", "2001:db8::1", ""},
		{"[2001:db8::1]", "ip6", "2001:db8::1", ""},
		{"2001:db8::1", "ip4", "", "not an IPv4 address"},
		{"192.0.2.1", "ip6", "", "not an IPv6 address"},
		{"", "", "", "cannot parse"},
		{"[localhost]", "", "", "cannot parse"},
		// /etc/hosts has localhost as 127.0.0.1, and usually as ::1 too: IPv4 first.
		{"localhost", "", "127.0.0.1", ""},
		{"localhost", "ip4", "127.0.0.1", ""},
	} {
		got, err := ResolveAddr(ctx, tc.host, tc.network)
		if tc.err != "" {
			require.ErrorContains(t, err, tc.err, tc.host)
			continue
		}
		require.NoError(t, err, tc.host)
		require.Equal(t, tc.want, got.String(), tc.host)
	}
}

func TestGnbInterfaceAddrs(t *testing.T) {
	v4, v6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	dual := GnbInterface{IPv4Port: IPv4Port{netip.AddrPortFrom(v4, 2152)}, IPv6: v6}
	only6 := GnbInterface{IPv4Port: IPv4Port{netip.AddrPortFrom(v6, 2152)}}

	a, b := dual.Addrs()
	require.Equal(t, []netip.Addr{v4, v6}, []netip.Addr{a, b})
	a, b = only6.Addrs()
	require.Equal(t, []netip.Addr{{}, v6}, []netip.Addr{a, b})
	require.True(t, dual.HasIPv4() && dual.HasIPv6())
	require.True(t, !only6.HasIPv4() && only6.HasIPv6())
	addr, ok := only6.AddrOf(IPv4)
	require.False(t, ok)
	require.False(t, addr.IsValid())

	next := dual.WithNextAddr()
	require.Equal(t, "192.0.2.2:2152", next.AddrPort.String())
	require.Equal(t, "2001:db8::2", next.IPv6.String())
	require.Equal(t, "192.0.2.1:2152 and [2001:db8::1]:2152", dual.String())
	require.Equal(t, "[2001:db8::1]:9487", only6.WithPort(9487).String())
	require.False(t, dual.WithoutDualStack().HasIPv6())
	require.Equal(t, IPv4, FamilyOf(netip.AddrFrom16(v4.As16())))
	require.Equal(t, IPv6, FamilyOf(v6))
}

func TestResolveTunnelBackendN3IPv6(t *testing.T) {
	saved := tunnelBackends
	t.Cleanup(func() { tunnelBackends = saved })
	available := func() error { return nil }
	tunnelBackends = append(tunnelBackends[:0:0], tunnelBackends...)
	for i := range tunnelBackends {
		tunnelBackends[i].unavailable = available
	}
	only6 := GnbInterface{IPv4Port: IPv4Port{netip.MustParseAddrPort("[2001:db8::1]:2152")}}
	dual := GnbInterface{IPv4Port: IPv4Port{netip.MustParseAddrPort("192.0.2.1:2152")}, IPv6: netip.MustParseAddr("2001:db8::1")}

	_, err := ResolveTunnelBackend("gtp5g", PDUSessionIPv4, only6)
	require.ErrorContains(t, err, "cannot carry GTP-U over IPv6")
	backend, err := ResolveTunnelBackend("gtp5g", PDUSessionIPv4, dual)
	require.NoError(t, err)
	require.Equal(t, TunnelBackendGtp5g, backend)

	tunnelBackends[0].unavailable = func() error { return os.ErrNotExist } // no eBPF
	backend, err = ResolveTunnelBackend("auto", PDUSessionIPv4, only6)
	require.NoError(t, err)
	require.Equal(t, TunnelBackendUserspace, backend, "auto skips gtp5g for an IPv6-only N3")
	backend, err = ResolveTunnelBackend("auto", PDUSessionIPv4, dual)
	require.NoError(t, err)
	require.Equal(t, TunnelBackendGtp5g, backend)
}

// The example configurations load, and the default one is IPv4 as it was.
func TestExampleConfigs(t *testing.T) {
	for file, check := range map[string]func(Config){
		"config.yml": func(c Config) {
			require.Equal(t, "127.0.0.1:9487", c.GNodeB.ControlIF.String())
			require.False(t, c.GNodeB.DataIF.HasIPv6())
		},
		"config-ipv6.yml": func(c Config) {
			require.False(t, c.GNodeB.ControlIF.HasIPv4() || c.GNodeB.DataIF.HasIPv4())
			require.True(t, c.AMFs[0].Addr().Is6())
		},
		"config-dual-stack.yml": func(c Config) {
			require.True(t, c.GNodeB.ControlIF.HasIPv4() && c.GNodeB.ControlIF.HasIPv6())
			require.True(t, c.GNodeB.DataIF.HasIPv4() && c.GNodeB.DataIF.HasIPv6())
		},
	} {
		path, err := filepath.Abs(file)
		require.NoError(t, err)
		check(readConfig(path))
	}
}
