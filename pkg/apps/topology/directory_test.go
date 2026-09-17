package topology

import (
	"context"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/peeria"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
)

var directoryIA = addr.MustIAFrom(20, 0xfd0000000041)

// directoryPublish calls the handler as the authenticated publisher.
func directoryPublish(
	ctx context.Context, svc *DirectoryService, publisher addr.IA, entry *nodev1.Entry,
) error {

	sctx := context.WithValue(ctx, peeria.AuthenticatedIAContextKey(), publisher)
	_, err := svc.Publish(sctx, connect.NewRequest(&nodev1.PublishRequest{Entry: entry}))
	return err
}

func directoryList(ctx context.Context, svc *DirectoryService) ([]DirectoryEntry, error) {
	resp, err := svc.List(ctx, connect.NewRequest(&nodev1.ListRequest{}))
	if err != nil {
		return nil, err
	}
	var out []DirectoryEntry
	for _, pb := range resp.Msg.Entries {
		entry, err := entryFromPB(pb)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, nil
}

func directoryEntryPB(control, rendezvous string, private bool) *nodev1.Entry {
	return &nodev1.Entry{ControlAddr: control, RendezvousAddr: rendezvous, Private: private}
}

// TestDirectoryPublishRecordsAuthenticatedIA checks the handlers record the
// authenticated ISD-AS: a publish claiming another ISD-AS is recorded under
// the authenticated one, and one without an authenticated ISD-AS never
// records.
func TestDirectoryPublishRecordsAuthenticatedIA(t *testing.T) {
	svc := &DirectoryService{Store: NewDirectoryStore()}
	entry := directoryEntryPB("192.0.2.7:30043", "192.0.2.7:30045", false)
	entry.IsdAs = uint64(addr.MustIAFrom(20, 0xfd0000000099)) // a false claim
	if err := directoryPublish(context.Background(), svc, directoryIA, entry); err != nil {
		t.Fatal(err)
	}
	entries, err := directoryList(context.Background(), svc)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !entries[0].IA.Equal(directoryIA) {
		t.Fatalf("entries = %v, want the authenticated %v only", entries, directoryIA)
	}
	if entries[0].ControlAddr != netip.MustParseAddrPort("192.0.2.7:30043") {
		t.Errorf("control address = %v", entries[0].ControlAddr)
	}
	if entries[0].RendezvousAddr != netip.MustParseAddrPort("192.0.2.7:30045") {
		t.Errorf("rendezvous address = %v", entries[0].RendezvousAddr)
	}

	if err := directoryPublish(context.Background(), svc, addr.IA(0),
		directoryEntryPB("192.0.2.7:30043", "192.0.2.7:30045", false)); err == nil {
		t.Error("a publish without an authenticated ISD-AS was recorded")
	}
	if err := directoryPublish(context.Background(), svc, directoryIA, nil); err == nil {
		t.Error("a publish without an entry was recorded")
	}
	if err := directoryPublish(context.Background(), svc, directoryIA,
		directoryEntryPB("nope", "192.0.2.7:30045", false)); err == nil {
		t.Error("a publish with a malformed address was recorded")
	}
}

// TestDirectoryExpiry checks the TTL: entries expire without refresh, the
// list serving only the fresh ones. The TTL's passage is a fake-time sleep
// in the bubble.
func TestDirectoryExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		svc := &DirectoryService{Store: NewDirectoryStore()}
		if err := directoryPublish(context.Background(), svc, directoryIA,
			directoryEntryPB("192.0.2.7:30043", "192.0.2.7:30045", false)); err != nil {
			t.Fatal(err)
		}
		other := addr.MustIAFrom(20, 0xfd0000000042)
		if err := directoryPublish(context.Background(), svc, other,
			directoryEntryPB("192.0.2.8:30043", "192.0.2.8:30045", false)); err != nil {
			t.Fatal(err)
		}

		// A refresh of the first publisher only.
		time.Sleep(NodeDirectoryTTL / 2)
		if err := directoryPublish(context.Background(), svc, directoryIA,
			directoryEntryPB("192.0.2.7:30043", "192.0.2.7:30045", false)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(NodeDirectoryTTL)
		entries, err := directoryList(context.Background(), svc)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || !entries[0].IA.Equal(directoryIA) {
			t.Fatalf("entries after the TTL = %v, want the refreshed one only", entries)
		}

		// Beyond every refresh, the directory empties.
		time.Sleep(2 * NodeDirectoryTTL)
		entries, err = directoryList(context.Background(), svc)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Errorf("entries beyond every TTL = %v, want none", entries)
		}
	})
}
