package dataplane

import (
	"sync"
	"testing"
	"testing/synctest"
)

// TestPacketPoolFillsRacingBatches checks that Gets racing to drain the
// blocks the pool makes each get a packet while it may make more: batches
// that together take the pool's size all fill, where a Get left waiting with
// packets still to make blocks the bubble.
func TestPacketPoolFillsRacingBatches(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const batches = 8
		for range 50 {
			pool := makePacketPool(batches*poolBlock, minHeadroom)
			var wg sync.WaitGroup
			for range batches {
				wg.Go(func() {
					for range poolBlock {
						pool.Get()
					}
				})
			}
			wg.Wait()
		}
	})
}

// TestPacketPoolMakesBlocksOnDemand checks that a pool makes its packets as
// its Gets find it empty, a block at a time and its size at most, and that a
// Get once every packet is out waits for one to come back.
func TestPacketPoolMakesBlocksOnDemand(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const size = poolBlock + 36
		pool := makePacketPool(size, minHeadroom)
		if got := len(pool.pool); got != 0 {
			t.Fatalf("a fresh pool holds %d packets, want none", got)
		}
		held := []*Packet{pool.Get()}
		if got := len(pool.pool); got != poolBlock-1 {
			t.Fatalf("the pool holds %d packets after its first Get, want the rest of a block, %d",
				got, poolBlock-1)
		}
		for range size - 1 {
			held = append(held, pool.Get())
		}
		if got, left := len(pool.pool), pool.blocks.left; got != 0 || left != 0 {
			t.Fatalf("the pool holds %d packets and has %d to make once all are out, want none", got, left)
		}
		got := make(chan *Packet, 1)
		go func() { got <- pool.Get() }()
		synctest.Wait()
		if len(got) != 0 {
			t.Fatal("a Get past the pool's size took a packet while every one was out")
		}
		pool.Put(held[0])
		if p := <-got; p != held[0] {
			t.Error("the waiting Get took a packet other than the one that came back")
		}
	})
}
