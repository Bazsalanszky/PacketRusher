/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2026 Valentin D'Emmanuele
 */

package userspace

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A UE whose solicitations go unanswered, then answered by an advertisement it must
// ignore, keeps soliciting, ever less often, until a valid one comes: the SMF may
// well answer only once the downlink of the session is set up. It then has the
// address of the advertised prefix and of the interface identifier of the SMF.
func TestSolicitUntilAdvertised(t *testing.T) {
	if os.Getenv("PACKETRUSHER_TUN_TEST") != "1" {
		t.Skip("set PACKETRUSHER_TUN_TEST=1 in a private network namespace with CAP_NET_ADMIN")
	}
	interval, maxInterval := solicitationInterval, maxSolicitationInterval
	solicitationInterval, maxSolicitationInterval = 20*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { solicitationInterval, maxSolicitationInterval = interval, maxInterval })

	upf, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 77, 6, 8), Port: 2152})
	require.NoError(t, err)
	t.Cleanup(func() { _ = upf.Close() })
	gnb := netip.MustParseAddrPort("127.77.6.1:2152")
	session, err := Open("prsolicit0", gnb.Addr(), Config{UPF: netip.MustParseAddr("127.77.6.8"), UplinkTEID: 5, DownlinkTEID: 6, QFI: 9})
	require.NoError(t, err)
	closed := false
	t.Cleanup(func() {
		if !closed {
			session.Close()
		}
	})

	linkLocal := netip.MustParseAddr("fe80::abcd:1234:5678:9abc")
	type result struct {
		address netip.Addr
		err     error
	}
	done := make(chan result, 1)
	go func() {
		address, err := session.Solicit(linkLocal)
		done <- result{address, err}
	}()

	advertise := func(packet []byte) {
		_, err := upf.WriteToUDPAddrPort(Encode(append(make([]byte, Headroom), packet...), 6, 9), gnb)
		require.NoError(t, err)
	}
	buf := make([]byte, 1500)
	var times []time.Time
	for n := 1; n <= 6; n++ {
		require.NoError(t, upf.SetReadDeadline(time.Now().Add(3*time.Second)))
		size, peer, err := upf.ReadFromUDPAddrPort(buf)
		require.NoError(t, err, "solicitation %d", n)
		require.Equal(t, gnb, peer)
		times = append(times, time.Now())
		teid, solicitation, err := Decode(buf[:size])
		require.NoError(t, err)
		require.Equal(t, uint32(5), teid)
		require.Equal(t, routerSolicitation(linkLocal)[Headroom:], solicitation)
		if n == 4 { // From a global address: ignored.
			advertise(ra("2001:db8::1", nil, pio("2001:db8:1:2::/64", 0x40, 60, 60)))
		}
	}
	// Three RTR_SOLICITATION_INTERVALs, then twice as long (40 ms), then the cap
	// (50 ms), with some leeway for when the reads return.
	require.GreaterOrEqual(t, times[4].Sub(times[3]), 30*time.Millisecond)
	require.GreaterOrEqual(t, times[5].Sub(times[4]), 35*time.Millisecond)
	select {
	case r := <-done:
		t.Fatalf("Solicit returned before a valid advertisement: %v %v", r.address, r.err)
	default:
	}

	advertise(ra("fe80::1", nil, pio("2001:db8:1:2::/64", 0x40, 60, 60)))
	select {
	case r := <-done:
		require.NoError(t, r.err)
		require.Equal(t, netip.MustParseAddr("2001:db8:1:2:abcd:1234:5678:9abc"), r.address)
	case <-time.After(3 * time.Second):
		t.Fatal("the advertised prefix was not taken")
	}

	// Closing the session ends a solicitation.
	go func() {
		address, err := session.Solicit(linkLocal)
		done <- result{address, err}
	}()
	require.NoError(t, upf.SetReadDeadline(time.Now().Add(3*time.Second)))
	_, _, err = upf.ReadFromUDPAddrPort(buf)
	require.NoError(t, err)
	session.Close()
	closed = true
	r := <-done
	require.True(t, errors.Is(r.err, net.ErrClosed), r.err)
}
