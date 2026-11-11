/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2026 Valentin D'Emmanuele
 */

package test

import (
	"my5G-RANTester/config"
	"my5G-RANTester/internal/control"
	"net/netip"
	"testing"

	"github.com/free5gc/nas/ie"
	"github.com/stretchr/testify/require"
)

// The UE requests PDU sessions of the configured type, asking for DNS servers of
// both versions, and the control socket reports the addresses the network gives
// it: the IPv4 one, and the link-local address of the IPv6 interface identifier,
// which stays until a UPF advertises a prefix; without a tunnel, none does. The
// mock core makes the identifier of the IPv4 address it allocates.
func TestIPv6PDUSessions(t *testing.T) {
	for _, tc := range []struct {
		sessionType config.PDUSessionType
		nas         uint8
		n2, n3, amf string
		ipv4        bool
	}{
		{config.PDUSessionIPv6, ie.PDUSessType_IPv6, "127.0.0.1:9495", "127.0.0.1:2160", "127.0.0.1:38430", false},
		{config.PDUSessionIPv4v6, ie.PDUSessType_IPv4v6, "127.0.0.1:9497", "127.0.0.1:2162", "127.0.0.1:38432", true},
	} {
		t.Run(string(tc.sessionType), func(t *testing.T) {
			socket, fiveGC := startControlTest(t, tc.n2, tc.n3, tc.amf, func(c *config.Config) { c.Ue.PDUSessionType = tc.sessionType })
			response, err := control.Call(socket, control.Request{UeId: 1, Action: "wait"})
			require.NoError(t, err)
			status := response.Ues[0]
			require.True(t, status.Ready)
			require.Equal(t, []int{1, 2}, status.PduSessions)
			require.Len(t, status.Addresses, 2)
			for i, addresses := range status.Addresses {
				require.Equal(t, i+1, addresses.PduSession)
				ipv6 := netip.MustParseAddr(addresses.IPv6)
				require.True(t, ipv6.IsLinkLocalUnicast(), ipv6)
				identifier := ipv6.As16()
				require.Equal(t, []byte{0, 0, 0, 0}, identifier[8:12])
				if !tc.ipv4 {
					require.Empty(t, addresses.IPv4)
					continue
				}
				ipv4 := netip.MustParseAddr(addresses.IPv4).As4()
				require.Equal(t, ipv4[:], identifier[12:])
			}

			ue, err := fiveGC.GetAMFContext().FindRegisteredUEByMsin("0000000120")
			require.NoError(t, err)
			for id := int32(1); id <= 2; id++ {
				sm, err := ue.GetSmContext(id)
				require.NoError(t, err)
				require.Equal(t, tc.nas, sm.GetPduSessionType())
				require.True(t, sm.ProtocolConfigurationOptions.DNSIPv4Request)
				require.True(t, sm.ProtocolConfigurationOptions.DNSIPv6Request)
			}
		})
	}
}
