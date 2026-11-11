/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2026 Forsway Scandinavia AB
 * © Copyright 2026 Valentin D'Emmanuele
 */
package context

import (
	"my5G-RANTester/config"
	gnbContext "my5G-RANTester/internal/control_test_engine/gnb/context"
	"my5G-RANTester/internal/control_test_engine/procedures"
	"my5G-RANTester/internal/control_test_engine/ue/scenario"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testTunnel struct{}

func (testTunnel) Release() {}

func TestPDUSessionIdentifiers(t *testing.T) {
	ue := &UEContext{}
	for _, id := range []uint8{0, 16, 255} {
		_, err := ue.GetPduSession(id)
		require.Error(t, err)
		require.Error(t, ue.DeletePduSession(id))
	}
	for id := uint8(1); id <= 15; id++ {
		session, err := ue.CreatePDUSession()
		require.NoError(t, err)
		require.Equal(t, id, session.Id)
		found, err := ue.GetPduSession(id)
		require.NoError(t, err)
		require.Same(t, session, found)
	}
	_, err := ue.CreatePDUSession()
	require.Error(t, err)
	require.NoError(t, ue.DeletePduSession(15))
	replacement, err := ue.CreatePDUSession()
	require.NoError(t, err)
	require.Equal(t, uint8(15), replacement.Id)
}

// Invalid IDs, including reserved ID 16, must be rejected before indexing the array.
func TestUePduSessionIdOutOfRangeIsRefused(t *testing.T) {
	ue := &UEContext{}
	for _, id := range []uint8{0, 16, 17, 200} {
		_, err := ue.GetPduSession(id)
		assert.Error(t, err, "get, id %d", id)
		assert.Error(t, ue.DeletePduSession(id), "delete, id %d", id)
	}
}

// The highest assigned PDU session ID remains accessible and releasable.
func TestUeLastPduSessionCanBeFoundAndReleased(t *testing.T) {
	ue := &UEContext{}
	for i := 0; i < 15; i++ {
		_, err := ue.CreatePDUSession()
		require.NoError(t, err)
	}
	pduSession, err := ue.GetPduSession(15)
	require.NoError(t, err)
	assert.Equal(t, uint8(15), pduSession.Id)
	require.NoError(t, ue.DeletePduSession(15))
	assert.Nil(t, ue.PduSession[14])
}

// With tunnels, a UE is ready once the interface of its first PDU session exists.
func TestReportStatusWaitsForTunnel(t *testing.T) {
	scenarioChan := make(chan scenario.ScenarioMessage, 1)
	ue := &UEContext{scenarioChan: scenarioChan, StateMM: MM5G_REGISTERED, TunnelMode: config.TunnelShared, gnbTx: make(chan gnbContext.UEMessage)}
	for id := 1; id <= 2; id++ {
		pduSession, err := ue.CreatePDUSession()
		require.NoError(t, err)
		pduSession.SetStateSM_PDU_SESSION_ACTIVE()
	}
	ue.ReportStatus(nil)
	require.Equal(t, []int{2}, (<-scenarioChan).Status.PduSessions)
	ue.PduSession[0].Tunnel = testTunnel{}
	ue.ReportStatus(nil)
	status := (<-scenarioChan).Status
	require.Equal(t, []int{1, 2}, status.PduSessions)
	require.True(t, status.Ready)
}

// A session with an IPv6 half is usable once the UE has its address in the prefix
// that the network advertises after the tunnel is set up, except on gtp5g, which
// only carries the IPv4 half. The status reports the addresses of the sessions. (Its
// scenario then completes Ready with the number of usable sessions.)
func TestReportStatusWaitsForIPv6(t *testing.T) {
	linkLocal, global := netip.MustParseAddr("fe80::7"), netip.MustParseAddr("2a0e:8f02:f07b:500::7")
	for name, tc := range map[string]struct {
		backend config.TunnelBackend
		mode    config.TunnelMode
		ipv4    bool
		waits   bool
	}{
		"IPv6, userspace":      {config.TunnelBackendUserspace, config.TunnelTun, false, true},
		"IPv4v6, userspace":    {config.TunnelBackendUserspace, config.TunnelTun, true, true},
		"IPv6, eBPF VRF":       {config.TunnelBackendEBPF, config.TunnelVrf, false, true},
		"IPv4v6, gtp5g":        {config.TunnelBackendGtp5g, config.TunnelTun, true, false},
		"IPv4v6, gtp5g shared": {config.TunnelBackendGtp5g, config.TunnelShared, true, false},
		"IPv6, no tunnel":      {"", config.TunnelDisabled, false, false},
	} {
		scenarioChan := make(chan scenario.ScenarioMessage, 1)
		ue := &UEContext{scenarioChan: scenarioChan, StateMM: MM5G_REGISTERED, TunnelMode: tc.mode, TunnelBackend: tc.backend, gnbTx: make(chan gnbContext.UEMessage)}
		pduSession, err := ue.CreatePDUSession()
		require.NoError(t, err)
		pduSession.SetStateSM_PDU_SESSION_ACTIVE()
		want := procedures.PduSessionAddresses{PduSession: 1, IPv6: linkLocal.String()}
		if tc.ipv4 {
			pduSession.SetIp([12]uint8{172, 250, 0, 5})
			want.IPv4 = "172.250.0.5"
		}
		pduSession.SetIPv6(linkLocal)
		if tc.mode != config.TunnelDisabled {
			pduSession.Tunnel = testTunnel{}
		}
		ue.ReportStatus(nil)
		status := (<-scenarioChan).Status
		if tc.waits {
			require.Empty(t, status.PduSessions, name)
			require.Empty(t, status.Addresses, name)
		} else {
			require.Equal(t, []int{1}, status.PduSessions, name)
			require.Equal(t, []procedures.PduSessionAddresses{want}, status.Addresses, name)
		}

		pduSession.SetIPv6(global) // The UPF advertised the prefix.
		want.IPv6 = global.String()
		ue.ReportStatus(nil)
		status = (<-scenarioChan).Status
		require.Equal(t, []int{1}, status.PduSessions, name)
		require.Equal(t, []procedures.PduSessionAddresses{want}, status.Addresses, name)
	}
}
