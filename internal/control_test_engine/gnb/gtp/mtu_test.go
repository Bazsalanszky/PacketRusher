/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2026 Valentin D'Emmanuele
 */
package gtp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTunnelMTU(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		n3, configured, want int // want 0: refused
		ipv6                 bool
	}{
		{"Ethernet", 1500, 0, 1456, false},
		{"jumbo frames", 9000, 0, 8956, true},
		{"loopback, beyond the largest IPv4 packet", 65536, 0, 65491, false},
		{"ue.tunnelmtu", 1500, 1400, 1400, true},
		{"ue.tunnelmtu beyond what N3 leaves", 1500, 1457, 0, false},
		{"ue.tunnelmtu below the IPv4 minimum", 1500, 67, 0, false},
		{"ue.tunnelmtu below the IPv6 minimum", 1500, 1279, 0, true},
		{"N3 too small for IPv6", 1300, 0, 0, true},
	} {
		got, err := tunnelMTU(tc.n3, tc.configured, tc.ipv6, false)
		require.Equal(t, tc.want, got, tc.name)
		require.Equal(t, tc.want == 0, err != nil, tc.name)
	}
}

// GTP-U over IPv6 costs 20 bytes more than over IPv4: 40 for its header, not 20.
func TestTunnelMTUOverIPv6(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		n3, configured, want int // want 0: refused
		ipv6                 bool
	}{
		{"Ethernet", 1500, 0, 1436, false},
		{"Ethernet, IPv6 PDU session", 1500, 0, 1436, true},
		{"ue.tunnelmtu", 1500, 1400, 1400, true},
		{"ue.tunnelmtu that only IPv4 leaves", 1500, 1456, 0, false},
		{"N3 at the IPv6 minimum, too small for an IPv6 PDU session", 1280, 0, 0, true},
		{"N3 at the IPv6 minimum", 1280, 0, 1216, false},
	} {
		got, err := tunnelMTU(tc.n3, tc.configured, tc.ipv6, true)
		require.Equal(t, tc.want, got, tc.name)
		require.Equal(t, tc.want == 0, err != nil, tc.name)
	}
}
