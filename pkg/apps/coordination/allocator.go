package coordination

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/fancl20/cion/pkg/apps/wireguard"
)

// allocate issues one host's address: the next free address in the owning
// node's slice of the tailnet range, keyed by the host's public key —
// unique by construction, stable per key, idempotent to repeat, nothing
// ever freed. The owning node is chosen at registration — the slice with
// the most free addresses, ties to the lowest ISD-AS, over slices the
// directory assigned and so cannot overlap — and the record never moves: a
// re-registering host changes nothing.
func allocate(key wireguard.PublicKey, directory wireguard.Directory) (
	wireguard.HostEntry, error) {

	// Admission is durable: the registry's own record answers a key it
	// already holds, without asking the seam again.
	for _, host := range directory.Hosts {
		if host.PublicKey == key {
			return host, nil
		}
	}

	// The freest slice takes the host; ties go to the lowest ISD-AS.
	var owner *wireguard.Entry
	free := 0
	for i := range directory.Nodes {
		entry := &directory.Nodes[i]
		count := freeAddresses(entry.Overlay, directory.Hosts)
		if count > free || (count == free && owner != nil &&
			uint64(entry.IA) < uint64(owner.IA)) {

			free = count
			owner = entry
		}
	}
	switch {
	case owner == nil:
		return wireguard.HostEntry{}, errors.New(
			"the directory holds no node entry to place a host in")
	case free == 0:
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
