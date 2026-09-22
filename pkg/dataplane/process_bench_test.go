package dataplane

import (
	"testing"
)

// BenchmarkProcessPkt measures the fast path through the real processPkt,
// one entry per reachable traffic class and path shape. Each iteration takes
// a packet from the pool, copies the template in, and processes it — the
// copy is the receive the benchmark cannot skip, because processing consumes
// the path. The pooled design owes the transit and outbound classes zero
// allocations and the inbound class its one documented net.UDPAddr; the
// disposition is asserted before the timer starts, so the benchmark cannot
// silently time a discard.
func BenchmarkProcessPkt(b *testing.B) {
	for _, tc := range benchCases {
		b.Run(tc.name, func(b *testing.B) {
			n := newBenchNode(b, benchRunConfig)
			tmpl := tc.build(b, n, benchPad)
			ingress := tc.ingress(n)
			pool := newTestPool(64, minHeadroom)
			proc := newPacketProcessor(n.d)

			p := fillBenchPacket(pool.Get(), tmpl, ingress)
			if disp := proc.processPkt(p); disp != tc.disposition {
				b.Fatalf("warm-up disposition = %d, want %d", disp, tc.disposition)
			}
			pool.Put(p)

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				p := fillBenchPacket(pool.Get(), tmpl, ingress)
				if proc.processPkt(p) != tc.disposition {
					b.Fatal("processing drifted off the asserted path")
				}
				pool.Put(p)
			}
		})
	}
}

// BenchmarkProcessSCMP measures the slow path's per-answer cost — the cost
// proposal 0012's notification cap bounds per unit of invalid traffic. A
// packet engineered to fail hop-expiry validation is driven through
// slowPathPacketProcessor.processPacket: path reversal, the quoted original,
// SCMP serialization, and the SCION header prepended into the buffer's
// headroom. The fast-path validation that routes the packet here is a
// BenchmarkProcessPkt shape and stays outside the timer.
func BenchmarkProcessSCMP(b *testing.B) {
	n := newBenchNode(b, benchRunConfig)
	tmpl := expiredTransitPacket(b, n.key)
	pool := newTestPool(64, minHeadroom)

	fast := newPacketProcessor(n.d)
	p := fillBenchPacket(pool.Get(), tmpl, n.if1)
	if disp := fast.processPkt(p); disp != pSlowPath {
		b.Fatalf("warm-up disposition = %d, want %d", disp, pSlowPath)
	}
	request := p.slowPathRequest
	pool.Put(p)

	slow := newSlowPathProcessor(n.d)
	p = fillBenchPacket(pool.Get(), tmpl, n.if1)
	p.slowPathRequest = request
	if err := slow.processPacket(p); err != nil {
		b.Fatalf("warm-up answer: %v", err)
	}
	pool.Put(p)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		p := fillBenchPacket(pool.Get(), tmpl, n.if1)
		p.slowPathRequest = request
		if err := slow.processPacket(p); err != nil {
			b.Fatal(err)
		}
		pool.Put(p)
	}
}
