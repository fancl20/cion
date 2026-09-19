package testnetwork

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/links"
	"github.com/fancl20/cion/pkg/trust"
)

// operatorChatToken is the telegram spec the labs pass as --enroll-auth: the
// operator's chat and the bot's token, the split on the first colon keeping
// the token's own intact.
const operatorChatToken = "-1002147483647:7:test"

// operatorBot is a local Bot API double the Telegram labs point their core
// at with TelegramAPI: it records the prompts the operator's phone would
// show and lets the test press their buttons. Long-poll semantics keep the
// authorizer's loop honest — an idle poll holds instead of spinning.
type operatorBot struct {
	mtx     sync.Mutex
	prompts []map[string]any
	updates []map[string]any
	nextID  int64
	// url is the double's base URL.
	url string
	// waiting is closed and rebuilt on every press, waking the long polls.
	waiting chan struct{}
}

func newOperatorBot(t *testing.T) *operatorBot {
	t.Helper()
	b := &operatorBot{waiting: make(chan struct{})}
	srv := httptest.NewServer(http.HandlerFunc(b.handle))
	t.Cleanup(srv.Close)
	b.url = srv.URL
	return b
}

// handle serves the Bot API's three calls.
func (b *operatorBot) handle(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		defer func() { _ = r.Body.Close() }()
		body, _ = io.ReadAll(r.Body)
	}
	switch r.URL.Path {
	case "/bot7:test/sendMessage":
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		b.mtx.Lock()
		b.prompts = append(b.prompts, m)
		b.mtx.Unlock()
		b.reply(w, map[string]any{"message_id": len(b.prompts)})
	case "/bot7:test/getUpdates":
		b.mtx.Lock()
		waiting := b.waiting
		b.mtx.Unlock()
		select {
		case <-waiting:
		case <-r.Context().Done():
			return
		case <-time.After(50 * time.Millisecond):
		}
		b.mtx.Lock()
		updates := b.updates
		b.updates = nil
		b.mtx.Unlock()
		b.reply(w, updates)
	case "/bot7:test/answerCallbackQuery":
		b.reply(w, true)
	default:
		http.Error(w, "unknown method", http.StatusNotFound)
	}
}

// reply answers one Bot API call with its envelope around the result.
func (b *operatorBot) reply(w http.ResponseWriter, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"result":`))
	_, _ = w.Write(raw)
	_, _ = w.Write([]byte("}"))
}

// press presses the prompt number i's button — 0 approve, 1 deny — from the
// configured chat.
func (b *operatorBot) press(t *testing.T, i, button int) {
	t.Helper()
	b.mtx.Lock()
	defer b.mtx.Unlock()
	keyboard := b.prompts[i]["reply_markup"].(map[string]any)["inline_keyboard"].([]any)
	row := keyboard[0].([]any)
	data := row[button].(map[string]any)["callback_data"].(string)
	b.nextID++
	b.updates = append(b.updates, map[string]any{
		"update_id": b.nextID,
		"callback_query": map[string]any{
			"id":   "1",
			"data": data,
			"message": map[string]any{
				"chat": map[string]any{"id": float64(-1002147483647)},
			},
		},
	})
	waiting := b.waiting
	b.waiting = make(chan struct{})
	close(waiting)
}

// promptCount returns the number of prompts the operator's phone shows.
func (b *operatorBot) promptCount() int {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	return len(b.prompts)
}

// holdsChain reports whether the node's trust database holds a valid chain
// for its own name — the enrollment these labs measure, for a joiner may
// converge its paths before any chain names it.
func holdsChain(n *assemblyNode) bool {
	chain, err := trust.NewestChain(context.Background(), n.app.TrustDB(),
		n.app.IA(), time.Now())
	return err == nil && chain != nil
}

// holdsNoChainFor reports whether the core holds no chain naming the joiner.
func holdsNoChainFor(core, joiner *assemblyNode) bool {
	chains, err := core.app.TrustDB().Chains(context.Background(),
		trust.ChainQuery{IA: joiner.app.IA()})
	return err == nil && len(chains) == 0
}

// enrollAuthCore boots a founding core with the given enrollment policy
// (ADR-0010) on its own loopback address.
func enrollAuthCore(t *testing.T, wpki *WebPKI, ip netip.Addr,
	enrollAuth, telegramAPI string) *assemblyNode {
	t.Helper()
	return bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = FreeUDPAddrOn(t, ip)
		cfg.Control = FreeUDPAddrOn(t, ip)
		cfg.CertFile = wpki.certFile
		cfg.KeyFile = wpki.keyFile
		cfg.EnrollAuth = enrollAuth
		cfg.TelegramAPI = telegramAPI
	})
}

// bootTelegramJoiner boots a joiner that enrolls with the given core.
func bootTelegramJoiner(t *testing.T, wpki *WebPKI, ip netip.Addr,
	core *assemblyNode) *assemblyNode {
	t.Helper()
	return bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = FreeUDPAddrOn(t, ip)
		cfg.Control = FreeUDPAddrOn(t, ip)
		cfg.Neighbors = []string{core.rendezvousOf()}
		cfg.RootCAs = wpki.pool
	})
}

// TestJoinByEnrollAuthCIDR is the CIDR authorizer's integration proof: the
// join lab with a prefix list admitting the joiner's range — identity by
// rendezvous, TRC by the domain channel, enrollment allowed by prefix, and
// the candidate established on its evidence.
func TestJoinByEnrollAuthCIDR(t *testing.T) {
	wpki := NewWebPKI(t)
	ipA, ipB := addrIP(0x61), addrIP(0x62)
	a := enrollAuthCore(t, wpki, ipA, "cidrs=127.0.0.0/8", "")
	b := bootTelegramJoiner(t, wpki, ipB, a)

	Poll(t, "the joiner's candidate on the core", func() bool {
		return entryOf(a, b.app.IA()) != nil
	})
	Poll(t, "the joiner enrolled by prefix", func() bool { return holdsChain(b) })
	Poll(t, "the candidate established on its evidence", func() bool {
		e := entryOf(a, b.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	ctx := context.Background()
	Poll(t, "the joiner reaches the core", func() bool {
		return pingFrom(ctx, b, a.app.IA(), a.host)
	})
}

// TestJoinByEnrollAuthTelegram is the Telegram authorizer's integration
// proof: the join lab with the operator's double — the joiner pends through
// retries, the operator presses approve, and enrollment completes within one
// retry interval.
func TestJoinByEnrollAuthTelegram(t *testing.T) {
	wpki := NewWebPKI(t)
	bot := newOperatorBot(t)
	ipA, ipB := addrIP(0x64), addrIP(0x65)
	a := enrollAuthCore(t, wpki, ipA,
		"telegram="+operatorChatToken, bot.url)
	b := bootTelegramJoiner(t, wpki, ipB, a)

	Poll(t, "the operator's prompt", func() bool { return bot.promptCount() == 1 })
	// The joiner pends through retries: no chain names it, and no second
	// prompt re-asks the one identity, while the retry cadence runs.
	time.Sleep(10 * fastPacing.Enrollment)
	if holdsChain(b) {
		t.Fatal("the joiner enrolled before the operator answered")
	}
	if got := bot.promptCount(); got != 1 {
		t.Errorf("prompts while pending = %d, want the one", got)
	}

	// The operator presses approve; enrollment completes on the retry
	// cadence — one retry interval, with room for the press to land.
	pressed := time.Now()
	bot.press(t, 0, 0)
	Poll(t, "the approved joiner to enroll", func() bool { return holdsChain(b) })
	if elapsed := time.Since(pressed); elapsed > 10*fastPacing.Enrollment {
		t.Errorf("approval landed in %s, want the retry cadence", elapsed)
	}
	ctx := context.Background()
	Poll(t, "the approved joiner to reach the core", func() bool {
		return pingFrom(ctx, b, a.app.IA(), a.host)
	})
}

// TestJoinByEnrollAuthTelegramRestart checks the core restart mid-join: the
// joiner's loop converges on the restarted core, a fresh prompt answers it —
// the restart forgot the pending one — and the enrolled node runs on with no
// prompt at all, its renewals the chain check's own, never the map's.
func TestJoinByEnrollAuthTelegramRestart(t *testing.T) {
	wpki := NewWebPKI(t)
	bot := newOperatorBot(t)
	ipA, ipB := addrIP(0x67), addrIP(0x68)
	a := enrollAuthCore(t, wpki, ipA, "telegram="+operatorChatToken, bot.url)
	b := bootTelegramJoiner(t, wpki, ipB, a)
	Poll(t, "the operator's first prompt", func() bool { return bot.promptCount() == 1 })

	// The core restarts mid-join: same state, same policy, no memory — the
	// control host carries the fixed endpoint and rendezvous ports, so the
	// joiner's retries converge on the fresh process.
	state := a.stateDir
	a.cancel()
	a.app.Close()
	bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = state
		cfg.Internal = FreeUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.certFile
		cfg.KeyFile = wpki.keyFile
		cfg.EnrollAuth = "telegram=" + operatorChatToken
		cfg.TelegramAPI = bot.url
	})

	// The joiner's loop converges and asks the fresh core, whose fresh
	// authorizer prompts again — a join still in flight asks again.
	Poll(t, "the operator's second prompt", func() bool { return bot.promptCount() == 2 })
	bot.press(t, 1, 0)
	Poll(t, "the joiner to enroll after the restart", func() bool { return holdsChain(b) })

	// The enrolled node runs on with no prompt at all.
	time.Sleep(20 * fastPacing.Enrollment)
	if got := bot.promptCount(); got != 2 {
		t.Errorf("prompts with an enrolled joiner = %d, want the two of the join", got)
	}
}

// TestJoinDeniedByEnrollAuth checks the negative: a joiner outside the
// prefix list never enrolls — its candidate mints and it answers the
// window's probes, alive and trying exactly as the grace rule reads it, yet
// no evidence ever establishes the link and no chain ever names it, on
// either side; and once it goes silent the window retires it.
func TestJoinDeniedByEnrollAuth(t *testing.T) {
	wpki := NewWebPKI(t)
	ipA, ipB := addrIP(0x6a), addrIP(0x6b)
	// A prefix list that admits nothing on the lab's loopback addressing.
	a := enrollAuthCore(t, wpki, ipA, "cidrs=10.0.0.0/8", "")
	b := bootTelegramJoiner(t, wpki, ipB, a)

	// The candidate mints on the core and stays unproven: the joiner keeps
	// answering the window's probes, so the grace holds it, but no evidence
	// ever establishes it — the joiner's chain never exists.
	Poll(t, "the joiner's candidate on the core", func() bool {
		e := entryOf(a, b.app.IA())
		return e != nil && e.State == links.StateCandidate
	})
	time.Sleep(2 * fastPacing.CandidateWindow)
	if e := entryOf(a, b.app.IA()); e == nil || e.State != links.StateCandidate {
		t.Fatalf("the denied joiner's entry = %v, want still the graced candidate", e)
	}
	if holdsChain(b) {
		t.Error("a joiner outside the prefix list enrolled")
	}
	if !holdsNoChainFor(a, b) {
		t.Error("the core issued a chain naming a joiner outside the prefix list")
	}

	// The joiner goes silent — a link no node establishes — and the window
	// retires its entry.
	b.cancel()
	b.app.Close()
	Poll(t, "the candidate to retire with the window", func() bool {
		e := entryOf(a, b.app.IA())
		return e != nil && e.State == links.StateRetired
	})
}

// TestJoinPendingNeverCompletes checks the unattended prompt: a Telegram
// prompt no operator answers never completes an enrollment — and holds no
// transport state on the core, pending being a verdict the retry loop
// consumes, not a connection held for a human's reaction time.
func TestJoinPendingNeverCompletes(t *testing.T) {
	wpki := NewWebPKI(t)
	bot := newOperatorBot(t)
	ipA, ipB := addrIP(0x6c), addrIP(0x6d)
	a := enrollAuthCore(t, wpki, ipA, "telegram="+operatorChatToken, bot.url)
	b := bootTelegramJoiner(t, wpki, ipB, a)

	Poll(t, "the operator's prompt", func() bool { return bot.promptCount() == 1 })
	// No operator answers; the joiner keeps pending and never enrolls.
	time.Sleep(30 * fastPacing.Enrollment)
	if holdsChain(b) {
		t.Error("an unattended prompt completed an enrollment")
	}
	if !holdsNoChainFor(a, b) {
		t.Error("an unattended prompt issued a chain")
	}
	if got := bot.promptCount(); got != 1 {
		t.Errorf("prompts while unattended = %d, want the one", got)
	}
}
