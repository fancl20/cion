package enrollauth

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/controlplane"
)

// botAPI is the Telegram Bot API's public base URL.
const botAPI = "https://api.telegram.org"

// The authorizer's own times: one prompt's verdict stands for a window — an
// approved identity allows and a denied one denies for its remainder, and
// the next ask past it prompts again, a stranger's persistence re-prompting
// on a window, not on every retry. The Bot API calls carry their own bounds
// besides: a short send timeout, so a slow API answers pending promptly
// rather than holding the request toward the joiner's attempt timeout, and
// a long-poll wait with the retry that paces its failures.
const (
	// decisionWindow is how long one prompt's verdict stands.
	decisionWindow = 10 * time.Minute
	// sendTimeout bounds one Bot API write.
	sendTimeout = 10 * time.Second
	// pollTimeout is the long-poll wait one getUpdates call asks the API to
	// hold.
	pollTimeout = 25 * time.Second
	// pollRetry paces a failed poll.
	pollRetry = time.Second
)

// TelegramConfig configures the Telegram authorizer.
type TelegramConfig struct {
	// API is the Bot API's base URL; empty is the public one.
	API string
	// Chat is the chat the prompts go to and the only one whose answers
	// count.
	Chat int64
	// Token is the bot's token. It rides the run argument and so the
	// process list — an accepted consequence of argument-driven
	// configuration, the file indirection deliberately not built.
	Token string
	// Window overrides how long one prompt's verdict stands; zero uses the
	// default.
	Window time.Duration
}

// Telegram is the enrollment authorizer of the operator's phone (ADR-0010):
// per new identity — the claimed ISD-AS and the subject key's fingerprint
// keyed together — it prompts the configured chat over the Bot API with the
// claimed name, the fingerprint, the source address, and an approve and a
// deny button, and answers on the long-polled callbacks, one prompt per
// identity inside a decision window. It speaks the API directly over
// net/http — no SDK, for a vendored tree prices every dependency, and the
// three calls this needs are plain HTTPS and JSON. Everything lives in
// memory: a restart forgets pending and denied entries, a join still in
// flight asks again, and a callback for an identity the new process never
// prompted is answered with exactly that and ignored.
type Telegram struct {
	api    string
	chat   int64
	token  string
	window time.Duration
	hc     *http.Client

	// mtx guards asks, shared by the enrollment handlers and the poll loop.
	mtx  sync.Mutex
	asks map[askKey]*decision
}

// askKey names one identity: the claimed ISD-AS and the subject key's
// fingerprint together, so two strangers claiming one name present two asks
// and the operator approves at most one — the name-taken check settles the
// loser on its next retry, exactly as it does today.
type askKey struct {
	ia   addr.IA
	skid string
}

// decision is one identity's standing verdict and the moment it stops
// standing.
type decision struct {
	verdict controlplane.EnrollmentVerdict
	expires time.Time
}

// NewTelegram builds the authorizer; Run launches its poll loop.
func NewTelegram(cfg TelegramConfig) *Telegram {
	api := cfg.API
	if api == "" {
		api = botAPI
	}
	window := cfg.Window
	if window == 0 {
		window = decisionWindow
	}
	return &Telegram{
		api:    api,
		chat:   cfg.Chat,
		token:  cfg.Token,
		window: window,
		hc:     &http.Client{},
		asks:   make(map[askKey]*decision),
	}
}

// Authorize answers a first issuance: a standing decision returns for its
// window's remainder, and the first ask — or the first past the window —
// sends the chat one prompt and pends. A prompt that cannot be sent denies:
// with the API unreachable enrollment fails closed, safe, but unavailable
// until it returns.
func (t *Telegram) Authorize(
	ctx context.Context,
	f controlplane.EnrollmentFacts,
) controlplane.EnrollmentVerdict {

	skid, err := cppki.SubjectKeyID(f.Key)
	if err != nil {
		return controlplane.EnrollmentDeny
	}
	key := askKey{ia: f.IA, skid: string(skid)}
	now := time.Now()
	t.mtx.Lock()
	if d, ok := t.asks[key]; ok && now.Before(d.expires) {
		verdict := d.verdict
		t.mtx.Unlock()
		return verdict
	}
	t.mtx.Unlock()
	if err := t.sendPrompt(ctx, f, skid); err != nil {
		slog.Warn("Sending the enrollment prompt; denying",
			"isd_as", f.IA, "source", f.Addr, "err", err)
		return controlplane.EnrollmentDeny
	}
	t.mtx.Lock()
	t.asks[key] = &decision{
		verdict: controlplane.EnrollmentPending,
		expires: now.Add(t.window),
	}
	t.mtx.Unlock()
	return controlplane.EnrollmentPending
}

// Run receives the answer buttons until the context is canceled: one
// getUpdates long poll after another, under the caller's supervision.
func (t *Telegram) Run(ctx context.Context) {
	var offset int64
	for ctx.Err() == nil {
		updates, err := t.getUpdates(ctx, offset)
		if err != nil {
			if ctx.Err() == nil {
				slog.Warn("Polling the Bot API", "err", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(pollRetry):
				}
			}
			continue
		}
		for _, u := range updates {
			offset = u.UpdateID + 1
			t.decide(ctx, u.Callback)
		}
	}
}

// getUpdates long-polls one batch of updates from the confirmed offset.
func (t *Telegram) getUpdates(ctx context.Context, offset int64) ([]tgUpdate, error) {
	ctx, cancel := context.WithTimeout(ctx, pollTimeout+pollRetry)
	defer cancel()
	return call[[]tgUpdate](t, ctx, "getUpdates", tgGetUpdates{
		Offset:  offset,
		Timeout: int(pollTimeout.Seconds()),
	})
}

// decide applies one answer button: only the configured chat's count — an
// answer from any other chat is logged and ignored — and only a pending
// identity is decided, its verdict standing for the window's remainder, the
// strong no-prompt guarantee being the chain check's, not the map's.
func (t *Telegram) decide(ctx context.Context, cb *tgCallbackQuery) {
	if cb == nil {
		return // an update that carries no answer button
	}
	if cb.Chat() != t.chat {
		slog.Warn("Ignoring an enrollment answer from another chat", "chat", cb.Chat())
		return
	}
	approve, key, ok := parseCallbackData(cb.Data)
	if !ok {
		slog.Warn("Ignoring a malformed enrollment answer", "data", cb.Data)
		return
	}
	t.mtx.Lock()
	d := t.asks[key]
	if d == nil || d.verdict != controlplane.EnrollmentPending ||
		!time.Now().Before(d.expires) {

		t.mtx.Unlock()
		t.answer(ctx, cb.ID, "no pending enrollment for this identity")
		return
	}
	if approve {
		d.verdict = controlplane.EnrollmentAllow
	} else {
		d.verdict = controlplane.EnrollmentDeny
	}
	t.mtx.Unlock()
	slog.Info("Enrollment decided", "isd_as", key.ia, "approved", approve)
	t.answer(ctx, cb.ID, fmt.Sprintf("enrollment of %s %s", key.ia,
		map[bool]string{true: "approved", false: "denied"}[approve]))
}

// answer acknowledges an answer button on the operator's phone.
func (t *Telegram) answer(ctx context.Context, id, text string) {
	actx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	if _, err := call[tgSent](t, actx, "answerCallbackQuery", tgAnswer{
		QueryID: id,
		Text:    text,
	}); err != nil {
		slog.Debug("Acknowledging an enrollment answer", "err", err)
	}
}

// sendPrompt sends the chat one message naming the joiner — the claimed
// name, the key fingerprint, the source address — with an approve and a
// deny button whose callback data carries the identity it answers.
func (t *Telegram) sendPrompt(
	ctx context.Context,
	f controlplane.EnrollmentFacts,
	skid []byte,
) error {

	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	_, err := call[tgSent](t, ctx, "sendMessage", tgSendMessage{
		ChatID: t.chat,
		Text: fmt.Sprintf("CION enrollment request\nISD-AS: %s\nKey: %s\nSource: %s",
			f.IA, hex.EncodeToString(skid), sourceOf(f)),
		ReplyMarkup: tgReplyMarkup{InlineKeyboard: [][]tgButton{{
			{Text: "Approve", CallbackData: callbackData(true, f.IA, skid)},
			{Text: "Deny", CallbackData: callbackData(false, f.IA, skid)},
		}}},
	})
	return err
}

// sourceOf renders the source address fact, unknown included.
func sourceOf(f controlplane.EnrollmentFacts) string {
	if f.Addr.IsValid() {
		return f.Addr.String()
	}
	return "unknown"
}

// callbackData encodes an answer button's identity — one action byte, the
// ISD-AS, the fingerprint — as hex, inside Telegram's sixty-four-byte cap: a
// SHA-1 fingerprint's 29 bytes encode to 58 characters.
func callbackData(approve bool, ia addr.IA, skid []byte) string {
	b := make([]byte, 0, 1+8+len(skid))
	b = append(b, map[bool]byte{true: 'a', false: 'd'}[approve])
	b = binary.BigEndian.AppendUint64(b, uint64(ia))
	return hex.EncodeToString(append(b, skid...))
}

// parseCallbackData decodes an answer button's identity.
func parseCallbackData(s string) (bool, askKey, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) < 1+8+1 {
		return false, askKey{}, false
	}
	var approve bool
	switch b[0] {
	case 'a':
		approve = true
	case 'd':
	default:
		return false, askKey{}, false
	}
	return approve, askKey{
		ia:   addr.IA(binary.BigEndian.Uint64(b[1:9])),
		skid: string(b[9:]),
	}, true
}

// call posts one Bot API method and decodes its envelope, the result
// parameter's type naming the method's own.
func call[T any](t *Telegram, ctx context.Context, method string, req any) (T, error) {
	var zero T
	body, err := json.Marshal(req)
	if err != nil {
		return zero, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/bot%s/%s", t.api, t.token, method), bytes.NewReader(body))
	if err != nil {
		return zero, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := t.hc.Do(httpReq)
	if err != nil {
		return zero, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return zero, err
	}
	var env struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Result      T      `json:"result"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return zero, err
	}
	if !env.OK {
		return zero, fmt.Errorf("%s: %s", method, env.Description)
	}
	return env.Result, nil
}

// The Bot API's JSON shapes, only as much as the three calls need.

// tgUpdate is one polled update; only the callback queries carry answers.
type tgUpdate struct {
	UpdateID int64            `json:"update_id"`
	Callback *tgCallbackQuery `json:"callback_query"`
}

// tgCallbackQuery is one answer button press.
type tgCallbackQuery struct {
	ID      string     `json:"id"`
	Data    string     `json:"data"`
	Message *tgMessage `json:"message"`
}

// Chat returns the chat the answer was pressed in; zero when the update
// carries no message to name one.
func (c *tgCallbackQuery) Chat() int64 {
	if c.Message == nil {
		return 0
	}
	return c.Message.Chat.ID
}

// tgMessage is the prompt an answer button rides on.
type tgMessage struct {
	Chat tgChat `json:"chat"`
}

// tgChat names a chat by its id.
type tgChat struct {
	ID int64 `json:"id"`
}

// tgSent is the message a send answers with.
type tgSent struct {
	MessageID int64 `json:"message_id"`
}

// tgSendMessage is one prompted message with its answer buttons.
type tgSendMessage struct {
	ChatID      int64         `json:"chat_id"`
	Text        string        `json:"text"`
	ReplyMarkup tgReplyMarkup `json:"reply_markup"`
}

// tgReplyMarkup carries a message's inline keyboard.
type tgReplyMarkup struct {
	InlineKeyboard [][]tgButton `json:"inline_keyboard"`
}

// tgButton is one inline keyboard button.
type tgButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

// tgGetUpdates long-polls for answer buttons from a confirmed offset.
type tgGetUpdates struct {
	Offset  int64 `json:"offset"`
	Timeout int   `json:"timeout"`
}

// tgAnswer acknowledges an answer button.
type tgAnswer struct {
	QueryID string `json:"callback_query_id"`
	Text    string `json:"text"`
}
