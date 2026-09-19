package enrollauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/controlplane"
)

// testChat is the configured chat of the authorizers under test.
const testChat = int64(-1002147483647)

// botDouble is a local Bot API double: it records the prompts sent and the
// acknowledgements answered, and long-polls the updates the test presses.
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

// prompt returns the recorded prompt number i.
func (d *botDouble) prompt(i int) tgSendMessage {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	return d.prompts[i]
}

// promptCount returns the number of prompts sent.
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

// factsOf builds one identity's facts.
func factsOf(t *testing.T, key crypto.PublicKey) controlplane.EnrollmentFacts {
	t.Helper()
	return controlplane.EnrollmentFacts{
		IA:   addr.MustIAFrom(20, 0xff0000000002),
		Key:  key,
		Addr: netip.MustParseAddrPort("198.51.100.7:41234"),
	}
}

// runTelegram builds an authorizer on the double and runs its poll loop
// until the test ends.
func runTelegram(t *testing.T, d *botDouble, mutate func(*TelegramConfig)) *Telegram {
	t.Helper()
	cfg := TelegramConfig{API: d.url, Chat: testChat, Token: "7:test"}
	if mutate != nil {
		mutate(&cfg)
	}
	telegram := NewTelegram(cfg)
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

// TestTelegramPromptAndDecide walks the authorizer's own rules (ADR-0010):
// the first ask prompts and pends, retries do not re-prompt, the configured
// chat's approve allows and deny denies, another chat's answer is ignored,
// and a callback for an identity this process never prompted is answered
// with exactly that and ignored.
func TestTelegramPromptAndDecide(t *testing.T) {
	d := newBotDouble(t)
	tg := runTelegram(t, d, nil)

	key := newKey(t)
	facts := factsOf(t, key)

	// The first ask prompts and pends.
	if got := tg.Authorize(context.Background(), facts); got != controlplane.EnrollmentPending {
		t.Fatalf("first ask verdict = %v, want pending", got)
	}
	waitFor(t, "the prompt to send", func() bool { return d.promptCount() == 1 })
	// The prompt names the joiner; its buttons answer the identity asked.
	prompt := d.prompt(0)
	if prompt.ChatID != testChat || prompt.Text == "" {
		t.Errorf("prompt = %+v, want one to the configured chat naming the joiner", prompt)
	}
	skid, err := cppki.SubjectKeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	buttons := prompt.ReplyMarkup.InlineKeyboard[0]
	if len(buttons) != 2 || buttons[0].Text != "Approve" || buttons[1].Text != "Deny" {
		t.Fatalf("prompt buttons = %+v, want an approve and a deny", buttons)
	}
	for i, approve := range []bool{true, false} {
		want, wantKey, ok := parseCallbackData(buttons[i].CallbackData)
		if !ok || want != approve || wantKey.skid != string(skid) || wantKey.ia != facts.IA {
			t.Errorf("button %d data = %q, want the identity it answers", i, buttons[i].CallbackData)
		}
	}

	// Retries within the window pend without re-sending: one prompt per
	// identity.
	if got := tg.Authorize(context.Background(), facts); got != controlplane.EnrollmentPending {
		t.Fatalf("retry verdict = %v, want pending", got)
	}
	if got := d.promptCount(); got != 1 {
		t.Errorf("prompts after a retry = %d, want the one", got)
	}

	// The configured chat's approve allows.
	d.press(testChat, buttons[0].CallbackData)
	waitFor(t, "the approve to land", func() bool {
		return tg.Authorize(context.Background(), facts) == controlplane.EnrollmentAllow
	})

	// Deny denies a fresh identity.
	key2 := newKey(t)
	facts2 := factsOf(t, key2)
	if got := tg.Authorize(context.Background(), facts2); got != controlplane.EnrollmentPending {
		t.Fatalf("second identity's first ask verdict = %v, want pending", got)
	}
	waitFor(t, "the second prompt to send", func() bool { return d.promptCount() == 2 })
	// An answer from any other chat is ignored. Its approve is pressed
	// first; the unknown-identity callback pressed after it is answered,
	// which proves by update order the stranger's press was processed
	// before the verdict below is read.
	d.press(testChat+1, d.prompt(1).ReplyMarkup.InlineKeyboard[0][0].CallbackData)
	strangerSkid, err := cppki.SubjectKeyID(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	d.press(testChat, callbackData(true, facts.IA, strangerSkid))
	waitFor(t, "the unknown callback to be acknowledged", func() bool {
		d.mtx.Lock()
		defer d.mtx.Unlock()
		for _, a := range d.answers {
			if a.Text == "no pending enrollment for this identity" {
				return true
			}
		}
		return false
	})
	// The stranger's chat did not approve: a callback for an identity this
	// process never prompted is answered with exactly that and ignored,
	// and another chat's answer counts not at all.
	if got := tg.Authorize(context.Background(), facts2); got != controlplane.EnrollmentPending {
		t.Fatalf("verdict after another chat's approve = %v, want the pending untouched", got)
	}
	d.press(testChat, d.prompt(1).ReplyMarkup.InlineKeyboard[0][1].CallbackData)
	waitFor(t, "the deny to land", func() bool {
		return tg.Authorize(context.Background(), facts2) == controlplane.EnrollmentDeny
	})
}

// TestTelegramSendFailureDenies checks the fail-closed rule: with the API
// unreachable, a prompt that cannot be sent denies — safe, but unavailable
// until the API returns.
func TestTelegramSendFailureDenies(t *testing.T) {
	d := newBotDouble(t)
	tg := runTelegram(t, d, nil)
	d.setFail(true)

	facts := factsOf(t, newKey(t))
	if got := tg.Authorize(context.Background(), facts); got != controlplane.EnrollmentDeny {
		t.Errorf("verdict with the API down = %v, want deny", got)
	}
}

// TestTelegramWindowExpiry checks the window's edges: a denied identity
// denies for the window and prompts again past it, and an approved one
// allows for the window's remainder — the strong no-prompt guarantee being
// the chain check's, not the map's.
func TestTelegramWindowExpiry(t *testing.T) {
	d := newBotDouble(t)
	tg := runTelegram(t, d, func(cfg *TelegramConfig) { cfg.Window = 100 * time.Millisecond })

	facts := factsOf(t, newKey(t))
	if got := tg.Authorize(context.Background(), facts); got != controlplane.EnrollmentPending {
		t.Fatalf("first ask verdict = %v, want pending", got)
	}
	waitFor(t, "the prompt to send", func() bool { return d.promptCount() == 1 })
	d.press(testChat, d.prompt(0).ReplyMarkup.InlineKeyboard[0][1].CallbackData)
	waitFor(t, "the deny to land", func() bool {
		return tg.Authorize(context.Background(), facts) == controlplane.EnrollmentDeny
	})
	// Past the window the same identity asks again: one prompt per identity
	// holds inside a window, not forever. The retry's own ask is what
	// re-prompts, exactly as the joiner's loop produces it.
	waitFor(t, "the window to expire and the retry to re-prompt", func() bool {
		return tg.Authorize(context.Background(), facts) == controlplane.EnrollmentPending
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

	facts := factsOf(t, newKey(t))
	if got := tg.Authorize(context.Background(), facts); got != controlplane.EnrollmentPending {
		t.Fatalf("first ask verdict = %v, want pending", got)
	}
	waitFor(t, "the prompt to send", func() bool { return d.promptCount() == 1 })
	d.press(testChat, d.prompt(0).ReplyMarkup.InlineKeyboard[0][0].CallbackData)
	waitFor(t, "the approve to land", func() bool {
		return tg.Authorize(context.Background(), facts) == controlplane.EnrollmentAllow
	})

	// A restart forgets the decision and asks again.
	tg2 := runTelegram(t, d, nil)
	if got := tg2.Authorize(context.Background(), facts); got != controlplane.EnrollmentPending {
		t.Errorf("a fresh instance's verdict = %v, want pending: it knows no decision", got)
	}
	waitFor(t, "the re-prompt to send", func() bool { return d.promptCount() == 2 })
}
