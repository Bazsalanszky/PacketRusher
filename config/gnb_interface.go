/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2026 Balázs Toldi
 */
package config

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/goccy/go-yaml"
)

// IPFamily is an IP version, as configured: "ipv4" or "ipv6".
type IPFamily string

const (
	IPv4 IPFamily = "ipv4"
	IPv6 IPFamily = "ipv6"
)

// FamilyOf returns the IP version of addr.
func FamilyOf(addr netip.Addr) IPFamily {
	if addr.Unmap().Is4() {
		return IPv4
	}
	return IPv6
}

// N3Advertise is what the gNB signals as its N3 address of a PDU session.
type N3Advertise string

const (
	// AdvertiseSelected signals the gNB's address of the IP version it uses towards
	// the UPF of the session: 32 or 128 bits, so the downlink comes in that version.
	AdvertiseSelected N3Advertise = "selected"
	// AdvertiseAll signals every address of the gNB, 160 bits for a dual-stack one,
	// and leaves the choice of the downlink's IP version to the core.
	AdvertiseAll N3Advertise = "all"
)

// GnbInterface is the N2 (controlif) or N3 (dataif) endpoint of the gNB: an address
// of either IP version in ip, and for a dual-stack gNB its IPv6 address in ipv6, both
// with port. ip may be left out when ipv6 is set.
type GnbInterface struct {
	IPv4Port            // ip and port: the address towards peers of its IP version
	IPv6     netip.Addr // ipv6: the IPv6 address of a dual-stack gNB, whose ip is IPv4

	// For dataif only. PreferredFamily is the IP version used towards a UPF that
	// signals both, among those the gNB has: IPv4 unless set to ipv6.
	PreferredFamily IPFamily
	// Advertise is what the gNB signals as its own N3 address: AdvertiseSelected
	// (the default) or AdvertiseAll.
	Advertise N3Advertise
}

var _ yaml.InterfaceUnmarshalerContext = &GnbInterface{}

// UnmarshalYAML implements yaml.InterfaceUnmarshalerContext interface.
func (v *GnbInterface) UnmarshalYAML(ctx context.Context, unmarshal func(interface{}) error) error {
	var value struct {
		IP              string      `yaml:"ip"`   // IPv4 or IPv6 address, or hostname
		IPv6            string      `yaml:"ipv6"` // IPv6 address or hostname
		Port            uint16      `yaml:"port"`
		PreferredFamily IPFamily    `yaml:"preferredfamily"`
		Advertise       N3Advertise `yaml:"advertise"`
	}
	if err := unmarshal(&value); err != nil {
		return err
	}
	parsed := GnbInterface{PreferredFamily: value.PreferredFamily, Advertise: value.Advertise}
	if value.IPv6 != "" {
		addr, err := ResolveAddr(ctx, value.IPv6, "ip6")
		if err != nil {
			return fmt.Errorf("ipv6: %w", err)
		}
		parsed.IPv6 = addr
	}
	if value.IP != "" || !parsed.IPv6.IsValid() {
		network := ""
		if parsed.IPv6.IsValid() {
			network = "ip4" // The IPv6 address is in ipv6.
		}
		addr, err := ResolveAddr(ctx, value.IP, network)
		if err != nil {
			return fmt.Errorf("ip: %w", err)
		}
		parsed.AddrPort = netip.AddrPortFrom(addr, value.Port)
	} else {
		parsed.AddrPort, parsed.IPv6 = netip.AddrPortFrom(parsed.IPv6, value.Port), netip.Addr{}
	}
	if err := parsed.Validate(); err != nil {
		return err
	}
	*v = parsed
	return nil
}

// Validate checks what UnmarshalYAML cannot express by itself.
func (v GnbInterface) Validate() error {
	if !v.Addr().IsValid() {
		return errors.New("an IPv4 or IPv6 address is required")
	}
	if v.IPv6.IsValid() && (!v.Addr().Is4() || !v.IPv6.Is6()) {
		return fmt.Errorf("ipv6 %s requires ip to be the IPv4 address, not %s", v.IPv6, v.Addr())
	}
	switch v.PreferredFamily {
	case "", IPv4, IPv6:
	default:
		return fmt.Errorf("preferredfamily must be %s or %s, not %q", IPv4, IPv6, v.PreferredFamily)
	}
	switch v.Advertise {
	case "", AdvertiseSelected, AdvertiseAll:
	default:
		return fmt.Errorf("advertise must be %s or %s, not %q", AdvertiseSelected, AdvertiseAll, v.Advertise)
	}
	return nil
}

// Addrs returns the IPv4 and the IPv6 address of the interface, either invalid if
// it has none.
func (v GnbInterface) Addrs() (v4, v6 netip.Addr) {
	if addr := v.Addr(); addr.Is4() {
		return addr, v.IPv6
	} else if addr.IsValid() {
		return netip.Addr{}, addr
	}
	return netip.Addr{}, v.IPv6
}

// AddrOf returns the interface's address of the IP version family, if it has one.
func (v GnbInterface) AddrOf(family IPFamily) (netip.Addr, bool) {
	v4, v6 := v.Addrs()
	if family == IPv4 {
		return v4, v4.IsValid()
	}
	return v6, v6.IsValid()
}

// HasIPv4 and HasIPv6 report whether the interface has an address of that version.
func (v GnbInterface) HasIPv4() bool { _, ok := v.AddrOf(IPv4); return ok }
func (v GnbInterface) HasIPv6() bool { _, ok := v.AddrOf(IPv6); return ok }

// WithNextAddr returns a copy with the next address of each IP version.
func (v GnbInterface) WithNextAddr() GnbInterface {
	v.IPv4Port = v.IPv4Port.WithNextAddr()
	if v.IPv6.IsValid() {
		v.IPv6 = v.IPv6.Next()
	}
	return v
}

// WithPort returns a copy with the specified port number.
func (v GnbInterface) WithPort(port uint16) GnbInterface {
	v.IPv4Port = v.IPv4Port.WithPort(port)
	return v
}

// WithoutDualStack returns a copy with only the address in ip.
func (v GnbInterface) WithoutDualStack() GnbInterface {
	v.IPv6 = netip.Addr{}
	return v
}

// String is the address and port, then the IPv6 address of a dual-stack interface.
func (v GnbInterface) String() string {
	if v.IPv6.IsValid() {
		return v.AddrPort.String() + " and " + netip.AddrPortFrom(v.IPv6, v.Port()).String()
	}
	return v.AddrPort.String()
}
