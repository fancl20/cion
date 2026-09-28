package telegram

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/enrollauth"
	"github.com/fancl20/cion/pkg/modules/enrollauth/impl/authtest"
)

// testChat is the configured chat of the authorizers under test.
const testChat = int64(-1002147483647)

// botDouble is a local Bot API double: it records the messages sent and the
// acknowledgements answered, and long-polls the updates the test presses and
// sends.
type botDouble struct {
	mtx     sync.Mutex
	prompts []tgSendMessage
	answers []tgAnswer
	updates []tgUpdate
	nextID  int64
	// url is the double's base URL.
	url string
	// waiting is closed and rebuilt on every press, waking the long polls.
	waiting chan struct{}
	// fail makes every send fail.
	fail bool
}

func newBotDouble(t *testing.T) *botDouble {
	t.Helper()
	d := &botDouble{waiting: make(chan struct{})}
	srv := httptest.NewServer(http.HandlerFunc(d.handle))
	t.Cleanup(srv.Close)
	d.url = srv.URL
	return d
}

// handle serves the Bot API's three calls.
func (d *botDouble) handle(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		defer func() { _ = r.Body.Close() }()
		body, _ = io.ReadAll(r.Body)
	}
	switch r.URL.Path {
	case "/bot7:test/sendMessage":
		d.mtx.Lock()
		fail := d.fail
		d.mtx.Unlock()
		if fail {
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		var m tgSendMessage
		if err := json.Unmarshal(body, &m); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		d.mtx.Lock()
		d.prompts = append(d.prompts, m)
		d.mtx.Unlock()
		writeJSON(w, tgSent{MessageID: 1})
	case "/bot7:test/getUpdates":
		// Long-poll semantics: hold until a press lands or a short wait
		// elapses, so an idle poll loop does not spin.
		d.mtx.Lock()
		waiting := d.waiting
		d.mtx.Unlock()
		select {
		case <-waiting:
		case <-r.Context().Done():
			return
		case <-time.After(50 * time.Millisecond):
		}
		d.mtx.Lock()
		updates := d.updates
		d.updates = nil
		d.mtx.Unlock()
		writeJSON(w, updates)
	case "/bot7:test/answerCallbackQuery":
		var a tgAnswer
		if err := json.Unmarshal(body, &a); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		d.mtx.Lock()
		d.answers = append(d.answers, a)
		d.mtx.Unlock()
		writeJSON(w, true)
	default:
		http.Error(w, "unknown method", http.StatusNotFound)
	}
}

// press enqueues one answer button press from the given chat.
func (d *botDouble) press(chat int64, data string) {
	d.mtx.Lock()
	d.nextID++
	d.updates = append(d.updates, tgUpdate{
		UpdateID: d.nextID,
		Callback: &tgCallbackQuery{
			ID:      fmt.Sprintf("%d", d.nextID),
			Data:    data,
			Message: &tgMessage{Chat: tgChat{ID: chat}},
		},
	})
	waiting := d.waiting
	d.waiting = make(chan struct{})
	d.mtx.Unlock()
	close(waiting)
}

// say enqueues one chat message from the given chat — the operator's own
// words, the invitation flow's side of the conversation.
func (d *botDouble) say(chat int64, text string) {
	d.mtx.Lock()
	d.nextID++
	d.updates = append(d.updates, tgUpdate{
		UpdateID: d.nextID,
		Message:  &tgMessage{Chat: tgChat{ID: chat}, Text: text},
	})
	waiting := d.waiting
	d.waiting = make(chan struct{})
	d.mtx.Unlock()
	close(waiting)
}

// prompt returns the recorded message number i.
func (d *botDouble) prompt(i int) tgSendMessage {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	return d.prompts[i]
}

// promptCount returns the number of messages sent.
func (d *botDouble) promptCount() int {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	return len(d.prompts)
}

// setFail makes every send fail.
func (d *botDouble) setFail(fail bool) {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	d.fail = fail
}

// writeJSON answers one Bot API call with its envelope around the result.
func writeJSON(w http.ResponseWriter, v any) {
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

// newKey generates a subject key for the facts of an ask.
func newKey(t *testing.T) crypto.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key.Public()
}

// skidOf fingerprints a subject key the way the trust service's call site
// does.
func skidOf(t *testing.T, key crypto.PublicKey) string {
	t.Helper()
	skid, err := cppki.SubjectKeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(skid)
}

// enrollFactsOf builds one node identity's facts at the enrollment
// boundary.
func enrollFactsOf(t *testing.T, key crypto.PublicKey) enrollauth.AdmissionFacts {
	t.Helper()
	return enrollauth.AdmissionFacts{
		Boundary: enrollauth.BoundaryEnrollment,
		Keys:     []string{skidOf(t, key)},
		Claim:    addr.MustIAFrom(20, 0xff0000000002),
		Source:   netip.MustParseAddrPort("198.51.100.7:41234"),
	}
}

// registerFactsOf builds one host identity's facts at the registration
// boundary — the machine and node keys a login presented, with an optional
// credential.
func registerFactsOf(t *testing.T, machine, node crypto.PublicKey,
	credential string) enrollauth.AdmissionFacts {

	t.Helper()
	return enrollauth.AdmissionFacts{
		Boundary:   enrollauth.BoundaryRegistration,
		Keys:       []string{skidOf(t, machine), skidOf(t, node)},
		Source:     netip.MustParseAddrPort("198.51.100.9:52331"),
		Credential: credential,
	}
}

// runTelegram builds an authorizer on the double and runs its poll loop
// until the test ends.
func runTelegram(t *testing.T, d *botDouble, mutate func(*Config)) *Authorizer {
	t.Helper()
	cfg := Config{
		API:   d.url,
		Chat:  testChat,
		Token: "7:test",
		State: t.TempDir(),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	telegram, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go telegram.Run(ctx)
	return telegram
}

// waitFor polls for a condition, failing the test at the timeout.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// pendingOf reads one ask's standing verdict.
func pendingOf(tg *Authorizer, ctx context.Context,
	f enrollauth.AdmissionFacts) enrollauth.AdmissionVerdict {

	return tg.Authorize(ctx, f).Admission
}

// TestTelegramPromptAndDecide walks the authorizer's own rules (ADR-0010):
// the first ask prompts and pends, retries do not re-prompt, the configured
// chat's approve allows and deny denies, another chat's answer is ignored,
// and a callback for an identity this process never prompted is answered
// with exactly that and ignored.
func TestTelegramPromptAndDecide(t *testing.T) {
	d := newBotDouble(t)
	tg := runTelegram(t, d, nil)

	key := newKey(t)
	facts := enrollFactsOf(t, key)

	// The first ask prompts and pends.
	if got := pendingOf(tg, context.Background(), facts); got != enrollauth.AdmissionPending {
		t.Fatalf("first ask verdict = %v, want pending", got)
	}
	waitFor(t, "the prompt to send", func() bool { return d.promptCount() == 1 })
	// The prompt names the joiner; its buttons answer the identity asked.
	prompt := d.prompt(0)
	if prompt.ChatID != testChat || prompt.Text == "" {
		t.Errorf("prompt = %+v, want one to the configured chat naming the joiner", prompt)
	}
	if !strings.Contains(prompt.Text, facts.Keys[0]) ||
		!strings.Contains(prompt.Text, facts.Claim.String()) {
		t.Errorf("prompt text = %q, want the claim and the fingerprint in it", prompt.Text)
	}
	buttons := prompt.ReplyMarkup.InlineKeyboard[0]
	if len(buttons) != 2 || buttons[0].Text != "Approve" || buttons[1].Text != "Deny" {
		t.Fatalf("prompt buttons = %+v, want an approve and a deny", buttons)
	}
	for i, approve := range []bool{true, false} {
		want, wantKey, ok := parseCallbackData(buttons[i].CallbackData)
		wantDigest := string(keyDigest(strings.Join(facts.Keys, ",")))
		if !ok || want != approve || wantKey.digest != wantDigest ||
			wantKey.claim != facts.Claim ||
			wantKey.boundary != enrollauth.BoundaryEnrollment {

			t.Errorf("button %d data = %q, want the identity it answers",
				i, buttons[i].CallbackData)
		}
	}

	// Retries within the window pend without re-sending: one prompt per
	// identity.
	if got := pendingOf(tg, context.Background(), facts); got != enrollauth.AdmissionPending {
		t.Fatalf("retry verdict = %v, want pending", got)
	}
	if got := d.promptCount(); got != 1 {
		t.Errorf("prompts after a retry = %d, want the one", got)
	}

	// The configured chat's approve allows, and the note names the plugin's
	// own account of the decision.
	d.press(testChat, buttons[0].CallbackData)
	waitFor(t, "the approve to land", func() bool {
		return pendingOf(tg, context.Background(), facts) == enrollauth.AdmissionAllow
	})
	if got := tg.Authorize(context.Background(), facts).Note; got == "" {
		t.Error("an approved decision carries no note for the registry to record")
	}

	// Deny denies a fresh identity.
	key2 := newKey(t)
	facts2 := enrollFactsOf(t, key2)
	if got := pendingOf(tg, context.Background(), facts2); got != enrollauth.AdmissionPending {
		t.Fatalf("second identity's first ask verdict = %v, want pending", got)
	}
	waitFor(t, "the second prompt to send", func() bool { return d.promptCount() == 2 })
	// An answer from any other chat is ignored. Its approve is pressed
	// first; the unknown-identity callback pressed after it is answered,
	// which proves by update order the stranger's press was processed
	// before the verdict below is read.
	d.press(testChat+1, d.prompt(1).ReplyMarkup.InlineKeyboard[0][0].CallbackData)
	stranger := enrollauth.AdmissionFacts{
		Boundary: enrollauth.BoundaryEnrollment,
		Keys:     []string{skidOf(t, newKey(t))},
		Claim:    facts.Claim,
	}
	d.press(testChat, callbackData(true, stranger))
	waitFor(t, "the unknown callback to be acknowledged", func() bool {
		d.mtx.Lock()
		defer d.mtx.Unlock()
		for _, a := range d.answers {
			if a.Text == "no pending admission for this identity" {
				return true
			}
		}
		return false
	})
	// The stranger's chat did not approve: a callback for an identity this
	// process never prompted is answered with exactly that and ignored,
	// and another chat's answer counts not at all.
	if got := pendingOf(tg, context.Background(), facts2); got != enrollauth.AdmissionPending {
		t.Fatalf("verdict after another chat's approve = %v, want the pending untouched", got)
	}
	d.press(testChat, d.prompt(1).ReplyMarkup.InlineKeyboard[0][1].CallbackData)
	waitFor(t, "the deny to land", func() bool {
		return pendingOf(tg, context.Background(), facts2) == enrollauth.AdmissionDeny
	})
}

// TestTelegramRegistrationPrompts checks the registration boundary's bare
// joiner: the machine and node fingerprints prompt the configured chat the
// same way, and the approve button answers that identity alone.
func TestTelegramRegistrationPrompts(t *testing.T) {
	d := newBotDouble(t)
	tg := runTelegram(t, d, nil)

	facts := registerFactsOf(t, newKey(t), newKey(t), "")
	if got := pendingOf(tg, context.Background(), facts); got != enrollauth.AdmissionPending {
		t.Fatalf("first ask verdict = %v, want pending", got)
	}
	waitFor(t, "the prompt to send", func() bool { return d.promptCount() == 1 })
	prompt := d.prompt(0)
	for _, key := range facts.Keys {
		if !strings.Contains(prompt.Text, key) {
			t.Errorf("prompt text = %q, want the fingerprint %s in it", prompt.Text, key)
		}
	}
	buttons := prompt.ReplyMarkup.InlineKeyboard[0]
	_, wantKey, ok := parseCallbackData(buttons[0].CallbackData)
	if !ok || wantKey.boundary != enrollauth.BoundaryRegistration {
		t.Errorf("button data = %q, want the registration identity", buttons[0].CallbackData)
	}
	// A different registration identity pends separately: one prompt per
	// identity, the machine and node keys together.
	other := registerFactsOf(t, newKey(t), newKey(t), "")
	if got := pendingOf(tg, context.Background(), other); got != enrollauth.AdmissionPending {
		t.Fatalf("a second identity's first ask verdict = %v, want pending", got)
	}
	waitFor(t, "the second prompt to send", func() bool { return d.promptCount() == 2 })

	d.press(testChat, buttons[0].CallbackData)
	waitFor(t, "the approve to land", func() bool {
		return pendingOf(tg, context.Background(), facts) == enrollauth.AdmissionAllow
	})
	if got := pendingOf(tg, context.Background(), other); got != enrollauth.AdmissionPending {
		t.Fatalf("the other identity after the first's approve = %v, want pending", got)
	}
}

// TestTelegramSendFailureDenies checks the fail-closed rule: with the API
// unreachable, a prompt that cannot be sent denies — safe, but unavailable
// until the API returns.
func TestTelegramSendFailureDenies(t *testing.T) {
	d := newBotDouble(t)
	tg := runTelegram(t, d, nil)
	d.setFail(true)

	facts := enrollFactsOf(t, newKey(t))
	if got := pendingOf(tg, context.Background(), facts); got != enrollauth.AdmissionDeny {
		t.Errorf("verdict with the API down = %v, want deny", got)
	}
}

// TestTelegramWindowExpiry checks the window's edges: a denied identity
// denies for the window and prompts again past it, and an approved one
// allows for the window's remainder — the strong no-prompt guarantee being
// the registry's, not the map's.
func TestTelegramWindowExpiry(t *testing.T) {
	d := newBotDouble(t)
	tg := runTelegram(t, d, func(cfg *Config) { cfg.Window = 100 * time.Millisecond })

	facts := enrollFactsOf(t, newKey(t))
	if got := pendingOf(tg, context.Background(), facts); got != enrollauth.AdmissionPending {
		t.Fatalf("first ask verdict = %v, want pending", got)
	}
	waitFor(t, "the prompt to send", func() bool { return d.promptCount() == 1 })
	d.press(testChat, d.prompt(0).ReplyMarkup.InlineKeyboard[0][1].CallbackData)
	waitFor(t, "the deny to land", func() bool {
		return pendingOf(tg, context.Background(), facts) == enrollauth.AdmissionDeny
	})
	// Past the window the same identity asks again: one prompt per identity
	// holds inside a window, not forever. The retry's own ask is what
	// re-prompts, exactly as the joiner's loop produces it.
	waitFor(t, "the window to expire and the retry to re-prompt", func() bool {
		return pendingOf(tg, context.Background(), facts) == enrollauth.AdmissionPending
	})
	if got := d.promptCount(); got != 2 {
		t.Errorf("prompts past the window = %d, want the re-prompt", got)
	}
}

// TestTelegramRestart checks the in-memory rule: a fresh instance — a
// restart — knows no decision, so a join still in flight asks again.
func TestTelegramRestart(t *testing.T) {
	d := newBotDouble(t)
	tg := runTelegram(t, d, nil)

	facts := enrollFactsOf(t, newKey(t))
	if got := pendingOf(tg, context.Background(), facts); got != enrollauth.AdmissionPending {
		t.Fatalf("first ask verdict = %v, want pending", got)
	}
	waitFor(t, "the prompt to send", func() bool { return d.promptCount() == 1 })
	d.press(testChat, d.prompt(0).ReplyMarkup.InlineKeyboard[0][0].CallbackData)
	waitFor(t, "the approve to land", func() bool {
		return pendingOf(tg, context.Background(), facts) == enrollauth.AdmissionAllow
	})

	// A restart forgets the decision and asks again.
	tg2 := runTelegram(t, d, nil)
	if got := pendingOf(tg2, context.Background(), facts); got != enrollauth.AdmissionPending {
		t.Errorf("a fresh instance's verdict = %v, want pending: it knows no decision", got)
	}
	waitFor(t, "the re-prompt to send", func() bool { return d.promptCount() == 2 })
}

// TestTelegramLogsNoToken checks the log hygiene of proposal 0015: a failed
// send or poll logs the method and the failure — `sendMessage failed`, the
// cause — never the URL the bot's token rides in.
func TestTelegramLogsNoToken(t *testing.T) {
	// An API host that refuses every connection.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	dead.Close()

	var buf lockedBuffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	tg, err := New(Config{
		API: dead.URL, Chat: testChat, Token: "7:test", State: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if got := pendingOf(tg, context.Background(), enrollFactsOf(t, newKey(t))); got != enrollauth.AdmissionDeny {
		t.Fatalf("verdict with the API down = %v, want deny", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go tg.Run(ctx)
	waitFor(t, "the failed poll to log", func() bool {
		return strings.Contains(buf.String(), "getUpdates failed")
	})

	logged := buf.String()
	if strings.Contains(logged, "7:test") || strings.Contains(logged, dead.URL) {
		t.Errorf("a Bot API failure logged the credential: %s", logged)
	}
	if !strings.Contains(logged, "sendMessage failed") {
		t.Errorf("log = %s, want the failed send's method and cause", logged)
	}
}

// lockedBuffer collects the log lines of the goroutines that share it.
type lockedBuffer struct {
	mtx sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	return b.buf.String()
}

// TestTelegramSweepExpiredDecisions checks the decision map's bound
// (proposal 0015): entries whose window has passed are dropped when the
// poll loop sweeps, so a stranger's persistent identities cost their
// prompts and nothing after.
func TestTelegramSweepExpiredDecisions(t *testing.T) {
	d := newBotDouble(t)
	tg := runTelegram(t, d, func(cfg *Config) { cfg.Window = 100 * time.Millisecond })

	facts := enrollFactsOf(t, newKey(t))
	if got := pendingOf(tg, context.Background(), facts); got != enrollauth.AdmissionPending {
		t.Fatalf("first ask verdict = %v, want pending", got)
	}
	waitFor(t, "the prompt to send", func() bool { return d.promptCount() == 1 })
	tg.mtx.Lock()
	held := len(tg.asks)
	tg.mtx.Unlock()
	if held != 1 {
		t.Fatalf("map entries = %d, want 1", held)
	}

	// Past the window the poll loop's sweep drops the entry; the map never
	// forgets nothing, but no longer everything.
	waitFor(t, "the expired decision to leave the map", func() bool {
		tg.mtx.Lock()
		defer tg.mtx.Unlock()
		return len(tg.asks) == 0
	})
}

// lastInvitation waits for the operator's mint request to be answered and
// returns the invitation the reply carries.
func lastInvitation(t *testing.T, d *botDouble) string {
	t.Helper()
	waitFor(t, "the minted invitation's reply", func() bool {
		if d.promptCount() == 0 {
			return false
		}
		return strings.Contains(d.prompt(d.promptCount()-1).Text, invitePrefix)
	})
	for _, line := range strings.Split(d.prompt(d.promptCount()-1).Text, "\n") {
		if strings.HasPrefix(line, invitePrefix) {
			return line
		}
	}
	t.Fatalf("reply = %q, want an invitation in it", d.prompt(d.promptCount()-1).Text)
	return ""
}

// TestTelegramInvitation walks the invitation flow (ADR-0011): the
// configured chat asks, the bot mints and replies, a registration presenting
// the unspent key approves and spends it, and a second presentation is a
// bare joiner's prompt — a stale invitation fails toward the human, not
// closed. Another chat can neither mint nor retire.
func TestTelegramInvitation(t *testing.T) {
	d := newBotDouble(t)
	tg := runTelegram(t, d, nil)

	// Another chat's mint request is ignored: the configured chat is the
	// only console. Its update is ordered before the configured chat's, so
	// by the time the mint's reply arrived, the stranger's was processed —
	// and produced nothing.
	d.say(testChat+1, "invite")
	d.say(testChat, "invite")
	key := lastInvitation(t, d)
	if got := d.promptCount(); got != 1 {
		t.Fatalf("messages after both mints = %d, want the configured chat's one", got)
	}

	// A registration presenting the unspent key approves and spends it.
	presented := registerFactsOf(t, newKey(t), newKey(t), key)
	answer := tg.Authorize(context.Background(), presented)
	if answer.Admission != enrollauth.AdmissionAllow {
		t.Fatalf("an invited registration's verdict = %v, want allow", answer.Admission)
	}
	if answer.Note == "" {
		t.Error("an invited approval carries no note for the registry to record")
	}

	// The spent key is a bare joiner's: the next presentation prompts.
	bare := registerFactsOf(t, newKey(t), newKey(t), key)
	if got := pendingOf(tg, context.Background(), bare); got != enrollauth.AdmissionPending {
		t.Fatalf("a spent invitation's verdict = %v, want the bare joiner's pending", got)
	}
	waitFor(t, "the bare joiner's prompt to send", func() bool {
		return d.promptCount() == 2
	})

	// An unknown credential prompts the same way.
	unknown := registerFactsOf(t, newKey(t), newKey(t), invitePrefix+"deadbeef")
	if got := pendingOf(tg, context.Background(), unknown); got != enrollauth.AdmissionPending {
		t.Fatalf("an unknown credential's verdict = %v, want the bare joiner's pending", got)
	}
}

// TestTelegramInvitationPersistence checks the invitations' own state: an
// unspent key survives a restart in the state directory and is answerable
// after it, a spent one is gone for good, and a retired one — sent back by
// the operator — prompts as a bare joiner's. One instance answers one
// double per phase, the way one process runs per core.
func TestTelegramInvitationPersistence(t *testing.T) {
	state := t.TempDir()

	// The first instance mints at its operator's request.
	d1 := newBotDouble(t)
	runTelegram(t, d1, func(cfg *Config) { cfg.State = state })
	d1.say(testChat, "invite")
	key := lastInvitation(t, d1)

	// A restart carries the unspent invitation; the fresh instance spends
	// it on presentation, and the spent key prompts the next time.
	d2 := newBotDouble(t)
	second, err := New(Config{
		API: d2.url, Chat: testChat, Token: "7:test", State: state})
	if err != nil {
		t.Fatal(err)
	}
	invited := registerFactsOf(t, newKey(t), newKey(t), key)
	if got := second.Authorize(context.Background(), invited).Admission; got != enrollauth.AdmissionAllow {
		t.Fatalf("a surviving invitation's verdict = %v, want allow", got)
	}
	if got := second.Authorize(context.Background(),
		registerFactsOf(t, newKey(t), newKey(t), key)).Admission; got != enrollauth.AdmissionPending {

		t.Fatalf("the spent invitation's second presentation = %v, want the bare pending", got)
	}

	// Retirement is conversational: the operator sends an unspent key back,
	// the bot retires it, and the next presentation prompts.
	d3 := newBotDouble(t)
	runTelegram(t, d3, func(cfg *Config) { cfg.State = state })
	d3.say(testChat, "invite")
	key2 := lastInvitation(t, d3)
	d3.say(testChat, key2)
	waitFor(t, "the retirement's reply", func() bool {
		last := d3.prompt(d3.promptCount() - 1).Text
		return strings.Contains(last, "retired")
	})
	raw, err := os.ReadFile(filepath.Join(state, "enrollauth", invitationsFile))
	if err != nil {
		t.Fatalf("reading the persisted invitations: %v", err)
	}
	var keys []string
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatalf("parsing the persisted invitations: %v", err)
	}
	for _, k := range keys {
		if k == key2 {
			t.Errorf("the retired invitation %q persists", key2)
		}
	}

	// A restart after the retirement still knows the invitation is spent.
	d4 := newBotDouble(t)
	third, err := New(Config{
		API: d4.url, Chat: testChat, Token: "7:test", State: state})
	if err != nil {
		t.Fatal(err)
	}
	retired := registerFactsOf(t, newKey(t), newKey(t), key2)
	if got := third.Authorize(context.Background(), retired).Admission; got != enrollauth.AdmissionPending {
		t.Fatalf("a retired invitation's verdict = %v, want the bare joiner's pending", got)
	}
}

// TestTelegramInvitationsRequireState checks the persistence precondition:
// an authorizer with no state directory configured refuses to build — a
// lost invitation file must never be a silent behavior — and a mint
// persists exactly the unspent set.
func TestTelegramInvitationsRequireState(t *testing.T) {
	_, err := New(Config{Chat: testChat, Token: "7:test"})
	if err == nil {
		t.Fatal("building without a state directory succeeded, want refusal")
	}

	state := t.TempDir()
	tg, err := New(Config{
		Chat: testChat, Token: "7:test", State: state})
	if err != nil {
		t.Fatal(err)
	}
	key := tg.mintInvite()
	raw, err := os.ReadFile(filepath.Join(state, "enrollauth", invitationsFile))
	if err != nil {
		t.Fatalf("reading the persisted invitations: %v", err)
	}
	var keys []string
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatalf("parsing the persisted invitations: %v", err)
	}
	if len(keys) != 1 || keys[0] != key {
		t.Fatalf("persisted invitations = %v, want the one minted %q", keys, key)
	}
}

// TestContract runs the module's shared contract suite: the fail-closed
// input is a prompt the API cannot carry.
func TestContract(t *testing.T) {
	d := newBotDouble(t)
	d.setFail(true)
	auth, err := New(Config{
		API:   d.url,
		Chat:  testChat,
		Token: "7:test",
		State: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	authtest.Run(t, authtest.Suite{
		New: func(t *testing.T) enrollauth.AdmissionAuthorizer { return auth },
		Facts: func(t *testing.T) enrollauth.AdmissionFacts {
			return enrollFactsOf(t, newKey(t))
		},
	})
}
