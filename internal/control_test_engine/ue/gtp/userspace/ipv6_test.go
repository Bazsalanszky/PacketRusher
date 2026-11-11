/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2026 Valentin D'Emmanuele
 */

package userspace

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRouterDiscovery(t *testing.T) {
	// fe80::7 asks all routers; fe80::1 advertises 2001:db8:1:2::/64 to all nodes.
	solicitation, _ := hex.DecodeString("6000000000083aff" + "fe800000000000000000000000000007" +
		"ff020000000000000000000000000002" + "85007d3000000000")
	advertisement, _ := hex.DecodeString("6000000000303aff" + "fe800000000000000000000000000001" +
		"ff020000000000000000000000000001" + "8600c386400007080000000000000000" +
		"030440c0ffffffffffffffff00000000" + "20010db8000100020000000000000000")
	require.Equal(t, solicitation, routerSolicitation(netip.MustParseAddr("fe80::7"))[Headroom:])

	change := func(index int, value byte) []byte {
		packet := bytes.Clone(advertisement)
		packet[index] = value
		return packet
	}
	fragment := append(change(6, 44)[:40], 58, 0, 0, 1, 0, 0, 0, 7) // more fragments follow
	none := netip.Prefix{}
	for name, tc := range map[string]struct {
		packet        []byte
		prefix        netip.Prefix
		advertisement bool
	}{
		"Router Advertisement":   {advertisement, netip.MustParsePrefix("2001:db8:1:2::/64"), true},
		"wrong checksum":         {change(87, 1), none, true},
		"Neighbor Advertisement": {change(40, 136), none, false},
		"fragment of ICMPv6":     {append(fragment, advertisement[40:]...), none, false},
		"IPv6 header only":       {advertisement[:40], none, false},
	} {
		ra, isAdvertisement, err := routerAdvertisement(tc.packet)
		require.Equal(t, tc.advertisement, isAdvertisement, name)
		require.Equal(t, tc.prefix, ra.prefix, name)
		require.Equal(t, tc.prefix.IsValid() || !isAdvertisement, err == nil, name)
	}
}

// pio is a Prefix Information option (RFC 4861 §4.6.2).
func pio(prefix string, flags byte, valid, preferred uint32) []byte {
	p := netip.MustParsePrefix(prefix)
	option := make([]byte, 32)
	option[0], option[1], option[2], option[3] = 3, 4, byte(p.Bits()), flags
	binary.BigEndian.PutUint32(option[4:], valid)
	binary.BigEndian.PutUint32(option[8:], preferred)
	copy(option[16:], p.Addr().AsSlice())
	return option
}

// ra is a Router Advertisement from source to all nodes with these options and a
// correct checksum, which edit may change before the checksum is computed.
func ra(source string, edit func(packet []byte) []byte, options ...[]byte) []byte {
	packet := make([]byte, 56)
	packet[0], packet[6], packet[7] = 0x60, 58, 255
	copy(packet[8:], netip.MustParseAddr(source).AsSlice())
	copy(packet[24:], netip.MustParseAddr("ff02::1").AsSlice())
	packet[40] = 134
	packet[44] = 64                               // cur hop limit
	binary.BigEndian.PutUint16(packet[46:], 1800) // router lifetime
	for _, option := range options {
		packet = append(packet, option...)
	}
	binary.BigEndian.PutUint16(packet[4:], uint16(len(packet)-40))
	if edit != nil {
		packet = edit(packet)
	}
	binary.BigEndian.PutUint16(packet[42:], checksum(packet))
	return packet
}

// The UE takes the first /64 it may autoconfigure an address in, from a valid
// Router Advertisement (RFC 4861 §6.1.2, RFC 4862 §5.5.3), and says why it ignores
// any other: the SMF's Router Advertisements are new, and so are their bugs.
func TestRouterAdvertisementValidation(t *testing.T) {
	const autonomous, onLink = 0x40, 0x80
	lab := pio("2a0e:8f02:f07b:500::/64", autonomous, 0xffffffff, 0xffffffff)
	mtu := []byte{5, 1, 0, 0, 0, 0, 0x05, 0xdc}
	set := func(index int, value byte) func([]byte) []byte {
		return func(packet []byte) []byte { packet[index] = value; return packet }
	}
	for name, tc := range map[string]struct {
		packet []byte
		prefix string // the prefix the UE takes, or else
		err    string // why it ignores the advertisement
		mtu    uint32
	}{
		// The 3GPP form: on-link flag clear (TS 29.061 §11.2.1.3.1), autonomous set.
		"SMF, L=0 A=1":            {packet: ra("fe80::1", nil, lab), prefix: "2a0e:8f02:f07b:500::/64"},
		"L=1 A=1":                 {packet: ra("fe80::1", nil, pio("2001:db8::/64", onLink|autonomous, 7200, 3600)), prefix: "2001:db8::/64"},
		"MTU option":              {packet: ra("fe80::1", nil, mtu, lab), prefix: "2a0e:8f02:f07b:500::/64", mtu: 1500},
		"bits after the length":   {packet: ra("fe80::1", nil, pio("2001:db8:0:1::99/64", autonomous, 60, 60)), prefix: "2001:db8:0:1::/64"},
		"second option is usable": {packet: ra("fe80::1", nil, pio("2001:db8:1::/64", 0, 60, 60), lab), prefix: "2a0e:8f02:f07b:500::/64"},
		"trailing bytes ignored":  {packet: append(ra("fe80::1", nil, lab), 0, 0, 0, 0), prefix: "2a0e:8f02:f07b:500::/64"},
		"unknown option skipped":  {packet: ra("fe80::1", nil, []byte{25, 1, 0, 0, 0, 0, 0, 0}, lab), prefix: "2a0e:8f02:f07b:500::/64"},

		"global source":          {packet: ra("2a0e:8f02:f07b:600::1", nil, lab), err: "not a link-local address"},
		"hop limit 64":           {packet: ra("fe80::1", set(7, 64), lab), err: "hop limit 64"},
		"code 1":                 {packet: ra("fe80::1", set(41, 1), lab), err: "ICMPv6 code 1"},
		"A=0":                    {packet: ra("fe80::1", nil, pio("2001:db8::/64", onLink, 60, 60)), err: "autonomous"},
		"/56":                    {packet: ra("fe80::1", nil, pio("2a0e:8f02:f07b:500::/56", autonomous, 60, 60)), err: "not a /64"},
		"link-local prefix":      {packet: ra("fe80::1", nil, pio("fe80::/64", autonomous, 60, 60)), err: "link-local"},
		"valid lifetime 0":       {packet: ra("fe80::1", nil, pio("2001:db8::/64", autonomous, 0, 0)), err: "valid lifetime 0"},
		"preferred beyond valid": {packet: ra("fe80::1", nil, pio("2001:db8::/64", autonomous, 60, 120)), err: "preferred lifetime 120 exceeds valid lifetime 60"},
		"no prefix":              {packet: ra("fe80::1", nil, mtu), err: "no Prefix Information option"},
		"zero-length option":     {packet: ra("fe80::1", nil, []byte{3, 0, 0, 0, 0, 0, 0, 0}, lab), err: "malformed option at byte 16"},
		"option overruns": {packet: ra("fe80::1", func(p []byte) []byte {
			p = p[:len(p)-8]
			binary.BigEndian.PutUint16(p[4:], uint16(len(p)-40))
			return p
		}, lab), err: "malformed option at byte 16"},
		"payload length too big": {packet: ra("fe80::1", set(5, 200), lab), err: "payload length 200 exceeds the 48 bytes received"},
		"too short":              {packet: ra("fe80::1", func(p []byte) []byte { p[5] = 12; return p[:52] }), err: "less than the 16"},
	} {
		advertisement, isAdvertisement, err := routerAdvertisement(tc.packet)
		require.True(t, isAdvertisement, name)
		if tc.err != "" {
			require.ErrorContains(t, err, tc.err, name)
			continue
		}
		require.NoError(t, err, name)
		require.Equal(t, netip.MustParsePrefix(tc.prefix), advertisement.prefix, name)
		require.Equal(t, netip.MustParseAddr("fe80::1"), advertisement.router, name)
		require.Equal(t, tc.mtu, advertisement.mtu, name)
	}

	advertisement, _, err := routerAdvertisement(ra("fe80::1", nil, mtu, lab))
	require.NoError(t, err)
	require.Equal(t, "prefix 2a0e:8f02:f07b:500::/64 from fe80::1, valid lifetime 4294967295s, preferred lifetime 4294967295s, MTU 1500", advertisement.String())

	// An odd-length message is checksummed as if padded with a zero byte.
	odd := ra("fe80::1", func(p []byte) []byte {
		p = append(p, 0xab)
		binary.BigEndian.PutUint16(p[4:], uint16(len(p)-40))
		return p
	}, lab)
	_, _, err = routerAdvertisement(odd)
	require.ErrorContains(t, err, "malformed option") // the checksum passed
}
