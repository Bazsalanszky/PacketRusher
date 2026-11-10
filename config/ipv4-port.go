package config

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/goccy/go-yaml"
)

// IPv4Port is a tuple of IP address and port number. Despite its name, kept for
// compatibility, the address may be IPv6.
type IPv4Port struct {
	netip.AddrPort
}

var _ yaml.InterfaceUnmarshalerContext = &IPv4Port{}

// UnmarshalYAML implements yaml.InterfaceUnmarshalerContext interface.
func (v *IPv4Port) UnmarshalYAML(ctx context.Context, unmarshal func(interface{}) error) error {
	var value struct {
		IP   string `yaml:"ip"`   // IPv4 or IPv6 address, or hostname
		Port uint16 `yaml:"port"` // port number
	}
	if e := unmarshal(&value); e != nil {
		return e
	}

	addr, e := ResolveAddr(ctx, value.IP, "")
	if e != nil {
		return e
	}
	v.AddrPort = netip.AddrPortFrom(addr, value.Port)
	return nil
}

// ResolveAddr returns the address that host designates: an IPv4 or IPv6 literal, the
// latter optionally in brackets, or a hostname. Network "ip4" or "ip6" restricts it to
// that version; with "" a hostname resolves to its IPv4 address if it has one, as it
// always did, and to its IPv6 address otherwise. IPv4-mapped addresses are unmapped.
func ResolveAddr(ctx context.Context, host, network string) (netip.Addr, error) {
	literal, bracketed := strings.CutPrefix(host, "[")
	if bracketed {
		literal, bracketed = strings.CutSuffix(literal, "]")
		if !bracketed {
			return netip.Addr{}, fmt.Errorf("cannot parse %q as an IP address or hostname", host)
		}
	}
	if addr, err := netip.ParseAddr(literal); err == nil {
		addr = addr.Unmap()
		if network == "ip4" && !addr.Is4() || network == "ip6" && !addr.Is6() {
			return netip.Addr{}, fmt.Errorf("%s is not an %s address", host, versionName(network))
		}
		return addr, nil
	}
	if literal != host || host == "" {
		return netip.Addr{}, fmt.Errorf("cannot parse %q as an IP address or hostname", host)
	}
	networks := []string{network}
	if network == "" {
		networks = []string{"ip4", "ip6"}
	}
	err := errors.New("no address")
	for _, network := range networks {
		ips, e := net.DefaultResolver.LookupNetIP(ctx, network, host)
		if e == nil && len(ips) > 0 {
			return ips[0].Unmap(), nil
		}
		if e != nil {
			err = e
		}
	}
	return netip.Addr{}, fmt.Errorf("cannot resolve %s as an %s address: %w", host, versionName(network), err)
}

func versionName(network string) string {
	switch network {
	case "ip4":
		return "IPv4"
	case "ip6":
		return "IPv6"
	}
	return "IP"
}

// WithNextAddr returns a copy of IPv4Port with the next IP address.
func (v IPv4Port) WithNextAddr() (copy IPv4Port) {
	copy.AddrPort = netip.AddrPortFrom(v.Addr().Next(), v.Port())
	return
}

// WithPort returns a copy of IPv4Port with the specified port number.
func (v IPv4Port) WithPort(port uint16) (copy IPv4Port) {
	copy.AddrPort = netip.AddrPortFrom(v.Addr(), port)
	return
}
