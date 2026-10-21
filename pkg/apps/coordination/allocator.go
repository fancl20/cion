package coordination

import (
	"fmt"
	"net/netip"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/apps/wireguard"
)

// allocate issues one host's address: the next free address in the named
// node's slice of the tailnet range, keyed by the host's public key —
// unique by construction, stable per key, idempotent to repeat. The node is
// the admission's to name, and the allocation is strict: a node the
// directory holds no entry of, an entry publishing no host endpoint, and a
// full slice each refuse rather than place the host elsewhere. The record
// never moves: a re-registering host changes nothing, whatever node its
// admission would name.
func allocate(key wireguard.PublicKey, directory wireguard.Directory, node addr.IA) (
	wireguard.HostEntry, error) {

	// Admission is durable: the registry's own record answers a key it
	// already holds, without asking the seam again.
	for _, host := range directory.Hosts {
		if host.PublicKey == key {
			return host, nil
		}
	}

	var owner *wireguard.Entry
	for i := range directory.Nodes {
		if directory.Nodes[i].IA.Equal(node) {
			owner = &directory.Nodes[i]
			break
		}
	}
	switch {
	case owner == nil:
		return wireguard.HostEntry{}, fmt.Errorf(
			"the directory holds no entry of %s to place a host in", node)
	case !owner.HostEndpoint.IsValid():
		return wireguard.HostEntry{}, fmt.Errorf(
			"%s publishes no host endpoint", node)
	case freeAddresses(owner.Overlay, directory.Hosts) == 0:
		return wireguard.HostEntry{}, fmt.Errorf(
			"the slice %s of %s is full", owner.Overlay, owner.IA)
	}

	taken := make(map[netip.Addr]bool, len(directory.Hosts))
	for _, host := range directory.Hosts {
		if owner.Overlay.Contains(host.Addr) {
			taken[host.Addr] = true
		}
	}
	// Allocation starts after the slice's first address — the node's own,
	// the netstack's claim on an egress node — and stops before the
	// broadcast.
	addr := firstAddress(owner.Overlay)
	for {
		addr = addr.Next()
		if !addr.IsValid() || !owner.Overlay.Contains(addr) || isBroadcast(addr, owner.Overlay) {
			return wireguard.HostEntry{}, fmt.Errorf(
				"the slice %s of %s is full", owner.Overlay, owner.IA)
		}
		if !taken[addr] {
			return wireguard.HostEntry{
				PublicKey: key,
				Addr:      addr,
				IA:        owner.IA,
			}, nil
		}
	}
}

// firstAddress returns a slice's first address — the node's own.
func firstAddress(prefix netip.Prefix) netip.Addr {
	return prefix.Masked().Addr().Next()
}

// isBroadcast reports whether addr is a slice's last address, reserved the
// way overlays reserve it.
func isBroadcast(addr netip.Addr, prefix netip.Prefix) bool {
	size := uint32(1) << (32 - prefix.Bits())
	last := prefix.Masked().Addr().As4()
	carry := size - 1
	for i := len(last) - 1; i >= 0; i-- {
		sum := uint32(last[i]) + carry
		last[i] = byte(sum)
		carry = sum >> 8
	}
	return addr == netip.AddrFrom4(last)
}

// freeAddresses counts a slice's allocatable addresses: every address but
// the network's own, the node's own first, and the broadcast — minus the
// ones the registry already issued.
func freeAddresses(prefix netip.Prefix, hosts []wireguard.HostEntry) int {
	if prefix.Bits() < 2 || prefix.Bits() > 30 {
		return 0
	}
	size := 1 << (32 - prefix.Bits())
	issued := 0
	for _, host := range hosts {
		if prefix.Contains(host.Addr) {
			issued++
		}
	}
	free := size - 2 /* network and broadcast */ -
		1 /* the node's own */ - issued
	if free < 0 {
		return 0
	}
	return free
}
