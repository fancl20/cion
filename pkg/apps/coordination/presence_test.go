package coordination

import (
	"bytes"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"tailscale.com/tailcfg"
)

// mapOnce answers one map request of the home host straight at the handler
// — a lite one when omitPeers is set — carrying the exit the client
// reports, and fails the test unless the map answers.
func mapOnce(t *testing.T, a *App, omitPeers bool, exit tailcfg.StableNodeID) {
	t.Helper()
	raw, err := json.Marshal(tailcfg.MapRequest{
		Version:   tailcfg.CurrentCapabilityVersion,
		NodeKey:   nodePublicOf(homeHost),
		OmitPeers: omitPeers,
		Hostinfo:  &tailcfg.Hostinfo{Hostname: "laptop", ExitNodeID: exit},
	})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.handleMap(w, httptest.NewRequest(http.MethodPost, "/machine/map", bytes.NewReader(raw)),
		machineZero())
	if w.Code != http.StatusOK {
		t.Fatalf("the map answered %d %s, want 200", w.Code, w.Body)
	}
}

// TestPresenceRecordsTheReportedExit checks the exit a host reports beside
// its presence: a map request naming a node's stable ID records that node,
// a lite request naming an ID no node holds records none, a lite request
// naming the home node's records it, and a later lite request naming none
// clears it.
func TestPresenceRecordsTheReportedExit(t *testing.T) {
	store := twoNodeRegistry(t)
	a := testApp(t, Config{Store: store})
	for _, step := range []struct {
		what      string
		omitPeers bool
		reported  tailcfg.StableNodeID
		want      addr.IA
	}{
		{"a request naming the other node", false, stableID(otherNode.PublicKey), otherNode.IA},
		{"a lite request naming an unknown ID", true, "nffffffffffff", 0},
		{"a lite request naming the home node", true, stableID(homeNode.PublicKey), homeNode.IA},
		{"a lite request naming none", true, "", 0},
	} {
		mapOnce(t, a, step.omitPeers, step.reported)
		seen, ok := a.Presence()[homeHost]
		if !ok {
			t.Fatalf("after %s the host holds no presence", step.what)
		}
		if seen.Exit != step.want {
			t.Errorf("after %s the presence's exit = %v, want %v", step.what, seen.Exit, step.want)
		}
	}
}
