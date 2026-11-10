/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2026 Balázs Toldi
 */

package service

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"my5G-RANTester/config"
	"my5G-RANTester/internal/control_test_engine/ue/context"
	"my5G-RANTester/internal/control_test_engine/ue/gtp/ebpfgtp"
)

// GTP-U over IPv6 (TS 29.281 §4.4) carries the UE's IPv4 PDU session between gNBs
// and a UPF on IPv6 N3 addresses. The userspace backend carries it, and so does the
// eBPF one, through userspace; a handover may move it to a gNB on IPv4 N3.
func TestTunnelOverIPv6(t *testing.T) {
	privilegedNetwork(t, "fd00:88:4::1", "fd00:88:4::2", "fd00:88:4::8", "fd00:88:4::9", "127.88.5.1")
	backends := []config.TunnelBackend{config.TunnelBackendUserspace}
	if ebpfgtp.Load() == nil {
		t.Cleanup(ebpfgtp.Close)
		backends = append(backends, config.TunnelBackendEBPF)
	}
	for number, backend := range backends {
		for _, mode := range []config.TunnelMode{config.TunnelTun, config.TunnelVrf} {
			t.Run(fmt.Sprintf("%s/%s", backend, []string{"policy", "VRF"}[mode-config.TunnelTun]), func(t *testing.T) {
				upf, otherUPF, upf4 := fakeUPF(t, "fd00:88:4::8"), fakeUPF(t, "fd00:88:4::9"), fakeUPF(t, "127.88.5.8")
				ue := &context.UEContext{TunnelMode: mode, TunnelBackend: backend, TunnelMTU: 3000}
				ue.UeSecurity.Msin = fmt.Sprintf("70055600%d%d", number, mode)
				session := &context.UEPDUSession{Id: 1}
				session.SetIp([12]uint8{10, 43, byte(number), byte(mode)})
				ue.PduSession[0] = session
				t.Cleanup(session.ReleaseTunnel)

				SetupGtpInterface(ue, message(t, "fd00:88:4::1", "fd00:88:4::8", 60, nil))
				require.NotNil(t, session.Tunnel)
				tunnel := session.Tunnel.(*tunnel)
				link, err := netlink.LinkByName(tunnel.link.Attrs().Name)
				require.NoError(t, err)
				require.Equal(t, 3000, link.Attrs().MTU, "the MTU is set from the IPv6 N3 interface")
				app := dialFromUE(t, session, net.ParseIP(session.GetIp()), "203.0.113.9:8888")
				echo(t, app, upf, "fd00:88:4::1", 60, 61)

				// Handover between gNBs on IPv6, then to another UPF.
				SetupGtpInterface(ue, message(t, "fd00:88:4::2", "fd00:88:4::8", 70, nil))
				echo(t, app, upf, "fd00:88:4::2", 70, 71)
				echoThrough(t, app, upf, "fd00:88:4::2", 70, "fd00:88:4::1", 61)
				tunnel.leave(tunnel.left)
				SetupGtpInterface(ue, message(t, "fd00:88:4::2", "fd00:88:4::9", 80, nil))
				echo(t, app, otherUPF, "fd00:88:4::2", 80, 81)

				// Handover to a gNB and a UPF on IPv4: the application keeps its socket.
				SetupGtpInterface(ue, message(t, "127.88.5.1", "127.88.5.8", 90, nil))
				echo(t, app, upf4, "127.88.5.1", 90, 91)
				released(t, ue, session)
			})
		}
	}
}

// gtp5g carries GTP-U over IPv4 only: an IPv6 N3 address or UPF gets no tunnel,
// rather than one that would never carry a packet.
func TestTunnelOverIPv6Gtp5g(t *testing.T) {
	privilegedNetwork(t, "fd00:88:4::11")
	ue := &context.UEContext{TunnelMode: config.TunnelTun, TunnelBackend: config.TunnelBackendGtp5g}
	ue.UeSecurity.Msin = "7005570001"
	session := &context.UEPDUSession{Id: 1}
	session.SetIp([12]uint8{10, 44, 0, 1})
	ue.PduSession[0] = session
	t.Cleanup(session.ReleaseTunnel)

	SetupGtpInterface(ue, message(t, "fd00:88:4::11", "fd00:88:4::8", 60, nil))
	require.Nil(t, session.Tunnel)
	SetupGtpInterface(ue, message(t, "127.88.5.11", "fd00:88:4::8", 60, nil))
	require.Nil(t, session.Tunnel)
	_, err := netlink.LinkByName("val" + ue.GetMsin())
	require.Error(t, err, "nothing is left behind")
}
