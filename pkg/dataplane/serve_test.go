package dataplane

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestServeDrainsOnCancellation serves a plane with several fast and slow-path
// slots, drives traffic through the processors, and cancels: the underlays
// stop, the slots drain their queues, and Serve returns nil with the
// processors' WaitGroup spent — the shutdown shape the unrecovered panic
// leaves untouched.
func TestServeDrainsOnCancellation(t *testing.T) {
	reader := newTestReader(t)
	rc := RunConfig{
		NumProcessors:         3,
		NumSlowPathProcessors: 2,
		BatchSize:             64,
		ReceiveBufferSize:     1 << 20,
		SendBufferSize:        1 << 20,
	}
	n := newBenchNode(t, rc)
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- n.d.Serve(ctx) }()

	// The internal link's bound address, where a local host writes.
	var internal *net.UDPAddr
	for _, c := range n.provider.allConnections {
		if !c.connected {
			internal = c.conn.conn.LocalAddr().(*net.UDPAddr)
		}
	}
	host, err := net.DialUDP("udp4", nil, internal)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()

	// SCION-like datagrams of one size class across varying flows: each is
	// invalid, so the sums settle only if the processors serve what the
	// internal link hashes to their queues.
	count := 12
	total := 700
	sc := ClassOfSize(total).String()
	want := map[metricKey]int64{
		{"dataplane.input_packets_total", "0", sc, ""}:          int64(count),
		{"dataplane.input_bytes_total", "0", sc, ""}:            int64(count * total),
		{"dataplane.processed_packets", "0", sc, ""}:            int64(count),
		{"dataplane.dropped_packets_total", "0", sc, "invalid"}: int64(count),
	}
	for i := range count {
		dgram := scionLikeDatagram(make([]byte, total-36))
		dgram[1] = byte(i) // The flow ID: spread across the queues.
		if _, err := host.Write(dgram); err != nil {
			t.Fatal(err)
		}
	}

	// The flushes are asynchronous; poll until the sums settle.
	deadline := time.Now().Add(testTimeout)
	for {
		sums := collectSums(t, reader)
		settled := true
		for k, v := range want {
			if sums[k] != v {
				settled = false
				break
			}
		}
		if settled {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("counters did not settle; got %v, want %v", sums, want)
		}
		time.Sleep(2 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve returned %v, want nil", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Serve did not return after cancellation")
	}
}
