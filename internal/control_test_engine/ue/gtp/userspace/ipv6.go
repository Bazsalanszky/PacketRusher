/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2026 Valentin D'Emmanuele
 */

package userspace

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// routerSolicitation returns the packet, after Headroom free bytes, by which the UE
// at the link-local address source asks the UPF for its prefix (RFC 4861 §4.1).
func routerSolicitation(source netip.Addr) []byte {
	b := make([]byte, Headroom+48)
	packet := b[Headroom:]
	packet[0], packet[5], packet[6], packet[7] = 0x60, 8, 58, 255 // 8 bytes of ICMPv6, hop limit 255
	copy(packet[8:], source.AsSlice())
	copy(packet[24:], netip.MustParseAddr("ff02::2").AsSlice()) // all routers
	packet[40] = 133
	binary.BigEndian.PutUint16(packet[42:], checksum(packet))
	return b
}

// advertisement is what the UE takes from a Router Advertisement.
type advertisement struct {
	router           netip.Addr   // its source, a link-local address
	prefix           netip.Prefix // the /64 for the UE's address
	valid, preferred uint32       // the lifetimes of that prefix, in seconds
	mtu              uint32       // of the MTU option, zero without one
}

func (a advertisement) String() string {
	s := fmt.Sprintf("prefix %s from %s, valid lifetime %ds, preferred lifetime %ds", a.prefix, a.router, a.valid, a.preferred)
	if a.mtu != 0 {
		s += fmt.Sprintf(", MTU %d", a.mtu)
	}
	return s
}

// routerAdvertisement reports whether packet is a Router Advertisement and, if a
// valid one (RFC 4861 §6.1.2), what it gives the UE to configure its address: the
// first Prefix Information option for autoconfiguration of a /64 (RFC 4862 §5.5.3).
// Otherwise err says why the UE ignores it. Only ICMPv6 that directly follows the
// IPv6 header is looked at: a fragment or a packet with extension headers is
// ordinary traffic.
//
// The on-link flag is not looked at: 3GPP networks clear it (TS 29.061 §11.2.1.3.1).
func routerAdvertisement(packet []byte) (ra advertisement, isAdvertisement bool, err error) {
	if len(packet) <= 40 || packet[0]>>4 != 6 || packet[6] != 58 || packet[40] != 134 {
		return ra, false, nil
	}
	// The IPv6 payload length bounds the message: what may follow is not part of it.
	length := 40 + int(binary.BigEndian.Uint16(packet[4:]))
	switch {
	case length > len(packet):
		return ra, true, fmt.Errorf("IPv6 payload length %d exceeds the %d bytes received", length-40, len(packet)-40)
	case length < 56:
		return ra, true, fmt.Errorf("%d bytes of ICMPv6, less than the 16 of a Router Advertisement", length-40)
	}
	packet = packet[:length]
	ra.router = netip.AddrFrom16([16]byte(packet[8:24]))
	switch {
	case !ra.router.IsLinkLocalUnicast():
		return ra, true, fmt.Errorf("source %s is not a link-local address", ra.router)
	case packet[7] != 255:
		return ra, true, fmt.Errorf("hop limit %d, not 255", packet[7])
	case packet[41] != 0:
		return ra, true, fmt.Errorf("ICMPv6 code %d, not 0", packet[41])
	case checksum(packet) != 0:
		return ra, true, errors.New("wrong ICMPv6 checksum")
	}
	var unusable error // why the first Prefix Information option was not taken
	for options := packet[56:]; len(options) != 0; options = options[8*int(options[1]):] {
		if len(options) < 2 || options[1] == 0 || 8*int(options[1]) > len(options) {
			return ra, true, fmt.Errorf("malformed option at byte %d of the ICMPv6 message", len(packet)-len(options)-40)
		}
		switch {
		case options[0] == 5 && options[1] == 1: // MTU
			ra.mtu = binary.BigEndian.Uint32(options[4:])
		case options[0] == 3 && options[1] == 4 && !ra.prefix.IsValid(): // Prefix Information
			prefix, err := autoconfiguration(options)
			if err == nil {
				ra.prefix, ra.valid, ra.preferred = prefix, binary.BigEndian.Uint32(options[4:]), binary.BigEndian.Uint32(options[8:])
			} else if unusable == nil {
				unusable = err
			}
		}
	}
	switch {
	case ra.prefix.IsValid():
		return ra, true, nil
	case unusable != nil:
		return ra, true, unusable
	}
	return ra, true, errors.New("no Prefix Information option")
}

// autoconfiguration returns the prefix of a Prefix Information option, if the UE may
// form its address there from the interface identifier the SMF allocated.
func autoconfiguration(option []byte) (netip.Prefix, error) {
	prefix := netip.PrefixFrom(netip.AddrFrom16([16]byte(option[16:32])), int(option[2]))
	valid, preferred := binary.BigEndian.Uint32(option[4:]), binary.BigEndian.Uint32(option[8:])
	switch {
	case option[3]&0x40 == 0:
		return prefix, fmt.Errorf("prefix %s: the autonomous address-configuration flag is not set", prefix)
	case option[2] != 64:
		return prefix, fmt.Errorf("prefix %s: not a /64, to which the 64-bit interface identifier would add up", prefix)
	case prefix.Addr().IsLinkLocalUnicast():
		return prefix, fmt.Errorf("prefix %s is link-local", prefix)
	case valid == 0:
		return prefix, fmt.Errorf("prefix %s: valid lifetime 0", prefix)
	case preferred > valid:
		return prefix, fmt.Errorf("prefix %s: preferred lifetime %d exceeds valid lifetime %d", prefix, preferred, valid)
	}
	return prefix.Masked(), nil // The bits after the prefix length are to be ignored.
}

// checksum computes the ICMPv6 checksum of an IPv6 packet without extension headers
// (RFC 4443 §2.3); it is zero if the packet carries a correct one.
func checksum(packet []byte) uint16 {
	sum := uint32(len(packet)-40) + 58 // pseudo-header: ICMPv6 length and next header
	for i := 8; i+1 < len(packet); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i:])) // addresses, then ICMPv6
	}
	if len(packet)%2 != 0 { // padded with a zero byte
		sum += uint32(packet[len(packet)-1]) << 8
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}
