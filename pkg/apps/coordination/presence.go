package coordination

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/scionproto/scion/pkg/addr"
	"tailscale.com/tailcfg"

	"github.com/fancl20/cion/pkg/apps/wireguard"
)

// claimCap bounds, in bytes, each claim a client makes of itself — its
// hostname and its operating system.
const claimCap = 64

// Presence is what the map handler last observed of one registered host:
// whether a map stream is open, when its last map request arrived or its
// last stream closed, and the hostname, operating system, and exit that
// request claimed. It lives in memory: a restart observes each host anew
// when it next maps.
type Presence struct {
	// Connected reports an open map stream.
	Connected bool
	// LastSeen is the last map request's arrival, or the last stream's
	// close when that came later.
	LastSeen time.Time
	// Hostname and OS are the client's latest claims about itself, capped
	// and stripped of control characters; empty where it claimed none.
	Hostname string
	OS       string
	// Exit is the node whose peer the client reports as its selected exit;
	// zero where it reports none or a stable ID no node holds.
	Exit addr.IA
}

// sighting is one host's presence as the map handler keeps it: the open
// streams beside the latest observation.
type sighting struct {
	streams  int
	lastSeen time.Time
	hostname string
	os       string
	exit     addr.IA
}

// Presence returns a snapshot of every registered host the map handler has
// observed since the application started, keyed by node key.
func (a *App) Presence() map[wireguard.PublicKey]Presence {
	a.presenceMtx.Lock()
	defer a.presenceMtx.Unlock()
	out := make(map[wireguard.PublicKey]Presence, len(a.presence))
	for key, s := range a.presence {
		out[key] = Presence{
			Connected: s.streams > 0,
			LastSeen:  s.lastSeen,
			Hostname:  s.hostname,
			OS:        s.os,
			Exit:      s.exit,
		}
	}
	return out
}

// observe records one map request of a registered host: the claims its
// hostinfo carries and the exit it reports, resolved against the directory
// the request was answered from. A client reports a change of exit only by
// a map request, so the request resolves it once and the snapshot reads no
// registry.
func (a *App) observe(key wireguard.PublicKey, hostinfo tailcfg.HostinfoView,
	directory wireguard.Directory) {

	hostname, osName := claimsOf(hostinfo)
	exit := reportedExit(hostinfo, directory)
	a.presenceMtx.Lock()
	defer a.presenceMtx.Unlock()
	s := a.presence[key]
	if s == nil {
		s = &sighting{}
		a.presence[key] = s
	}
	s.lastSeen = time.Now()
	s.hostname, s.os, s.exit = hostname, osName, exit
}

// streamOpened counts one open map stream of an observed host.
func (a *App) streamOpened(key wireguard.PublicKey) {
	a.presenceMtx.Lock()
	defer a.presenceMtx.Unlock()
	if s := a.presence[key]; s != nil {
		s.streams++
	}
}

// streamClosed retires one open map stream, its close the host's latest
// sighting. A host released while it streamed holds no entry to retire.
func (a *App) streamClosed(key wireguard.PublicKey) {
	a.presenceMtx.Lock()
	defer a.presenceMtx.Unlock()
	if s := a.presence[key]; s != nil {
		s.streams--
		s.lastSeen = time.Now()
	}
}

// forget drops a released host's presence.
func (a *App) forget(key wireguard.PublicKey) {
	a.presenceMtx.Lock()
	defer a.presenceMtx.Unlock()
	delete(a.presence, key)
}

// claimsOf reads the hostname and operating system a client claims of
// itself, each capped; empty when the request carries no hostinfo.
func claimsOf(hostinfo tailcfg.HostinfoView) (string, string) {
	if !hostinfo.Valid() {
		return "", ""
	}
	return capClaim(hostinfo.Hostname()), capClaim(hostinfo.OS())
}

// reportedExit resolves the exit a client reports — the stable ID of the
// peer it selected — to the directory node holding that ID: zero when the
// request carries no hostinfo, reports no exit, or names an ID no node
// holds.
func reportedExit(hostinfo tailcfg.HostinfoView, directory wireguard.Directory) addr.IA {
	if !hostinfo.Valid() || hostinfo.ExitNodeID().IsZero() {
		return 0
	}
	for _, node := range directory.Nodes {
		if stableID(node.PublicKey) == hostinfo.ExitNodeID() {
			return node.IA
		}
	}
	return 0
}

// capClaim strips control characters and invalid encoding from a claim and
// cuts it to claimCap bytes on a rune boundary.
func capClaim(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	if len(s) <= claimCap {
		return s
	}
	cut := claimCap
	for !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
