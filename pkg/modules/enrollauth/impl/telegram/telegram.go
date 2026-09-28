package telegram

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// botAPI is the Telegram Bot API's public base URL.
const botAPI = "https://api.telegram.org"

// The authorizer's own times: one prompt's verdict stands for a window — an
// approved identity allows and a denied one denies for its remainder, and the
// next ask past it prompts again, a stranger's persistence re-prompting on a
// window, not on every retry. The Bot API calls carry their own bounds
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

// invitePrefix marks a minted invitation among the credentials a
// registration may carry; inviteBytes is the random body's length.
const (
	invitePrefix = "cion-"
	inviteBytes  = 16
)

// invitationsFile holds the unspent invitations beneath the core's state.
const invitationsFile = "telegram-invitations.json"

// Config configures the Telegram authorizer.
type Config struct {
	// API is the Bot API's base URL; empty is the public one.
	API string
	// Chat is the chat the prompts go to and the only one whose answers
	// count — and the only one the operator can mint or retire invitations
	// from.
	Chat int64
	// Token is the bot's token. It rides the run argument and so the
	// process list — an accepted consequence of argument-driven
	// configuration, the file indirection deliberately not built.
	Token string
	// State is the core's state directory: the unspent invitations's
	// persistent home, so an invitation survives a restart while the
	// transient asks stay in memory.
	State string
	// Window overrides how long one prompt's verdict stands; zero uses the
	// default.
	Window time.Duration
}

// Authorizer is the admission authorizer of the operator's phone (ADR-0010,
// ADR-0011): per new identity — the boundary, the claim, and the presented
// keys' fingerprints keyed together — it prompts the configured chat over
// the Bot API with the facts and an approve and a deny button, and answers
// on the long-polled callbacks, one prompt per identity inside a decision
// window. The invitation reverses the flow: the operator asks the bot for a
// key in the configured chat, hands it to the headless client, and a
// registration presenting a key the plugin minted and has not spent approves
// on the plugin's own records and spends it; a spent or unknown key is a
// bare joiner's, prompted as ever — a stale invitation fails toward the
// human, not closed. It speaks the API directly over net/http — no SDK, for
// a vendored tree prices every dependency, and the handful of calls this
// needs are plain HTTPS and JSON. The prompts' decisions live in memory: a
// restart forgets pending and denied entries and a join still in flight
// asks again, while the unspent invitations persist in the state directory.
type Authorizer struct {
	api    string
	chat   int64
	token  string
	state  string
	window time.Duration
	hc     *http.Client

	// mtx guards asks and invites, shared by the admission handlers and the
	// poll loop.
	mtx     sync.Mutex
	asks    map[askKey]*decision
	invites map[string]struct{}
}

// askKey names one identity: the boundary asking, the enrollment's claim,
// and a digest of the presented keys' fingerprints, so two strangers
// claiming one name present two asks and the operator approves at most one
// — the name-taken check settles the loser on its next retry, exactly as it
// does today. The digest is what an answer button carries; the standing
// decision it resolves holds the fingerprints in full.
type askKey struct {
	boundary enrollauth.Boundary
	claim    addr.IA
	digest   string
}

// decision is one identity's standing verdict and the moment it stops
// standing.
type decision struct {
	admission enrollauth.AdmissionVerdict
	label     string
	expires   time.Time
}

// New builds the authorizer; Run launches its poll loop. Unspent
// invitations load from the state directory when its file exists.
func New(cfg Config) (*Authorizer, error) {
	api := cfg.API
	if api == "" {
		api = botAPI
	}
	window := cfg.Window
	if window == 0 {
		window = decisionWindow
	}
	t := &Authorizer{
		api:     api,
		chat:    cfg.Chat,
		token:   cfg.Token,
		state:   cfg.State,
		window:  window,
		hc:      &http.Client{},
		asks:    make(map[askKey]*decision),
		invites: make(map[string]struct{}),
	}
	if err := t.loadInvites(); err != nil {
		return nil, err
	}
	return t, nil
}

// Authorize answers one admission exchange. A registration presenting a
// credential the plugin minted and has not spent approves and spends it. A
// standing decision returns for its window's remainder, and the first ask —
// or the first past the window — sends the chat one prompt and pends. A
// prompt that cannot be sent denies: with the API unreachable admission
// fails closed, safe, but unavailable until it returns.
func (t *Authorizer) Authorize(
	ctx context.Context,
	f enrollauth.AdmissionFacts,
) enrollauth.AdmissionAnswer {

	if f.Boundary == enrollauth.BoundaryRegistration && f.Credential != "" {
		if t.spendInvite(f.Credential) {
			return enrollauth.AdmissionAnswer{
				Admission: enrollauth.AdmissionAllow,
				Note:      "telegram invitation",
			}
		}
	}
	if len(f.Keys) == 0 {
		return enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionDeny}
	}
	key := askKey{
		boundary: f.Boundary,
		claim:    f.Claim,
		digest:   string(keyDigest(identityOf(f))),
	}
	now := time.Now()
	t.mtx.Lock()
	if d, ok := t.asks[key]; ok && now.Before(d.expires) {
		answer := enrollauth.AdmissionAnswer{Admission: d.admission, Note: d.note()}
		t.mtx.Unlock()
		return answer
	}
	t.mtx.Unlock()
	if err := t.sendPrompt(ctx, f); err != nil {
		slog.Warn("Sending the admission prompt; denying",
			"boundary", f.Boundary, "claim", f.Claim, "source", f.Source, "err", err)
		return enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionDeny}
	}
	t.mtx.Lock()
	t.asks[key] = &decision{
		admission: enrollauth.AdmissionPending,
		label:     strings.Join(f.Keys, ","),
		expires:   now.Add(t.window),
	}
	t.mtx.Unlock()
	return enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionPending}
}

// note is the standing decision's own account of itself, the string the
// registry records beside an entry the prompt approved.
func (d *decision) note() string {
	switch d.admission {
	case enrollauth.AdmissionAllow:
		return "telegram operator"
	default:
		return ""
	}
}

// Run receives the operator's chat until the context is canceled: one
// getUpdates long poll after another, under the caller's supervision, each
// pass sweeping the decisions whose window has passed and answering the
// buttons pressed and the messages sent.
func (t *Authorizer) Run(ctx context.Context) {
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
		t.sweep()
		for _, u := range updates {
			offset = u.UpdateID + 1
			t.decide(ctx, u.Callback)
			t.converse(ctx, u.Message)
		}
	}
}

// sweep drops the decisions whose window has passed: a stranger's
// persistent identities cost their prompts and nothing after (proposal
// 0015).
func (t *Authorizer) sweep() {
	now := time.Now()
	t.mtx.Lock()
	defer t.mtx.Unlock()
	for key, d := range t.asks {
		if !now.Before(d.expires) {
			delete(t.asks, key)
		}
	}
}

// getUpdates long-polls one batch of updates from the confirmed offset.
func (t *Authorizer) getUpdates(ctx context.Context, offset int64) ([]tgUpdate, error) {
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
// strong no-prompt guarantee being the registry's, not the map's.
func (t *Authorizer) decide(ctx context.Context, cb *tgCallbackQuery) {
	if cb == nil {
		return // an update that carries no answer button
	}
	if cb.Chat() != t.chat {
		slog.Warn("Ignoring an admission answer from another chat", "chat", cb.Chat())
		return
	}
	approve, key, ok := parseCallbackData(cb.Data)
	if !ok {
		slog.Warn("Ignoring a malformed admission answer", "data", cb.Data)
		return
	}
	t.mtx.Lock()
	d := t.asks[key]
	if d == nil || d.admission != enrollauth.AdmissionPending ||
		!time.Now().Before(d.expires) {

		t.mtx.Unlock()
		t.answer(ctx, cb.ID, "no pending admission for this identity")
		return
	}
	if approve {
		d.admission = enrollauth.AdmissionAllow
	} else {
		d.admission = enrollauth.AdmissionDeny
	}
	label := d.label
	t.mtx.Unlock()
	slog.Info("Admission decided", "boundary", key.boundary,
		"claim", key.claim, "keys", label, "approved", approve)
	t.answer(ctx, cb.ID, fmt.Sprintf("admission of %s %s", label,
		map[bool]string{true: "approved", false: "denied"}[approve]))
}

// converse handles the operator's own messages — the invitation flow's
// mint and retire. Only the configured chat's count: it is the one chat the
// prompts went to, and the one channel this plugin treats as its console.
func (t *Authorizer) converse(ctx context.Context, msg *tgMessage) {
	if msg == nil {
		return // an update that carries no message
	}
	if msg.Chat.ID != t.chat {
		slog.Warn("Ignoring a message from another chat", "chat", msg.Chat.ID)
		return
	}
	text := strings.TrimSpace(msg.Text)
	switch {
	case strings.EqualFold(text, "invite"):
		key := t.mintInvite()
		slog.Info("Invitation minted", "chat", t.chat)
		t.reply(ctx, fmt.Sprintf("Invitation (one use):\n%s\nRetire it by sending it back.", key))
	case t.retireInvite(text):
		slog.Info("Invitation retired", "chat", t.chat)
		t.reply(ctx, "Invitation retired.")
	default:
		t.reply(ctx, "Send \"invite\" to mint an invitation, or an unspent one to retire it.")
	}
}

// mintInvite creates one unspent invitation and persists the set.
func (t *Authorizer) mintInvite() string {
	raw := make([]byte, inviteBytes)
	if _, err := rand.Read(raw); err != nil {
		// crypto/rand's failure is the process's own catastrophe; an empty
		// invitation can never be presented and so never admits.
		slog.Error("Minting an invitation", "err", err)
		return invitePrefix + strings.Repeat("0", 2*inviteBytes)
	}
	key := invitePrefix + hex.EncodeToString(raw)
	t.mtx.Lock()
	t.invites[key] = struct{}{}
	err := t.persistInvitesLocked()
	t.mtx.Unlock()
	if err != nil {
		slog.Warn("Persisting the invitations", "err", err)
	}
	return key
}

// spendInvite removes one unspent invitation and persists the set,
// reporting whether the credential spent.
func (t *Authorizer) spendInvite(key string) bool {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	if _, ok := t.invites[key]; !ok {
		return false
	}
	delete(t.invites, key)
	if err := t.persistInvitesLocked(); err != nil {
		slog.Warn("Persisting the invitations", "err", err)
	}
	return true
}

// retireInvite removes one unspent invitation by its own text and persists
// the set, reporting whether the text named one.
func (t *Authorizer) retireInvite(text string) bool {
	return t.spendInvite(text)
}

// loadInvites reads the persisted unspent invitations. A missing file is a
// fresh start; a present one the invitations an operator minted before the
// restart.
func (t *Authorizer) loadInvites() error {
	if t.state == "" {
		return errors.New("no state directory configured for the invitations")
	}
	raw, err := os.ReadFile(t.invitesPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("reading the invitations: %w", err)
	}
	var keys []string
	if err := json.Unmarshal(raw, &keys); err != nil {
		return fmt.Errorf("parsing the invitations: %w", err)
	}
	for _, key := range keys {
		t.invites[key] = struct{}{}
	}
	return nil
}

// persistInvitesLocked writes the unspent invitations back, atomically; the
// caller holds the mutex.
func (t *Authorizer) persistInvitesLocked() error {
	if t.state == "" {
		return nil
	}
	keys := make([]string, 0, len(t.invites))
	for key := range t.invites {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	raw, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	dir := filepath.Dir(t.invitesPath())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating the invitations' state: %w", err)
	}
	tmp := t.invitesPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("writing the invitations: %w", err)
	}
	return os.Rename(tmp, t.invitesPath())
}

func (t *Authorizer) invitesPath() string {
	return filepath.Join(t.state, "enrollauth", invitationsFile)
}

// answer acknowledges an answer button on the operator's phone.
func (t *Authorizer) answer(ctx context.Context, id, text string) {
	actx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	if _, err := call[tgSent](t, actx, "answerCallbackQuery", tgAnswer{
		QueryID: id,
		Text:    text,
	}); err != nil {
		slog.Debug("Acknowledging an admission answer", "err", err)
	}
}

// reply sends the chat one plain message — the invitation flow's side of
// the conversation.
func (t *Authorizer) reply(ctx context.Context, text string) {
	actx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	if _, err := call[tgSent](t, actx, "sendMessage", tgSendMessage{
		ChatID: t.chat,
		Text:   text,
	}); err != nil {
		slog.Warn("Replying in the operator's chat", "err", err)
	}
}

// sendPrompt sends the chat one message naming the joiner — the boundary,
// the claim, the fingerprints, the source address — with an approve and a
// deny button whose callback data carries the identity it answers.
func (t *Authorizer) sendPrompt(
	ctx context.Context,
	f enrollauth.AdmissionFacts,
) error {

	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	_, err := call[tgSent](t, ctx, "sendMessage", tgSendMessage{
		ChatID: t.chat,
		Text:   promptText(f),
		ReplyMarkup: tgReplyMarkup{InlineKeyboard: [][]tgButton{{
			{Text: "Approve", CallbackData: callbackData(true, f)},
			{Text: "Deny", CallbackData: callbackData(false, f)},
		}}},
	})
	return err
}

// identityOf is the stable identity an ask keys by and a button answers:
// the enrollment's subject key, the registration's machine key — the one
// fact that survives the client's own retries, for a registration attempt
// presents a freshly generated node key each time until one completes.
func identityOf(f enrollauth.AdmissionFacts) string {
	if f.Boundary == enrollauth.BoundaryRegistration {
		return f.Keys[0]
	}
	return strings.Join(f.Keys, ",")
}

// promptText renders one prompt: the enrollment's claimed name, the
// registration's offered keys, the source beside them.
func promptText(f enrollauth.AdmissionFacts) string {
	var b strings.Builder
	switch f.Boundary {
	case enrollauth.BoundaryRegistration:
		b.WriteString("CION registration request")
	default:
		b.WriteString("CION enrollment request")
	}
	if !f.Claim.IsZero() {
		fmt.Fprintf(&b, "\nISD-AS: %s", f.Claim)
	}
	for _, key := range f.Keys {
		fmt.Fprintf(&b, "\nKey: %s", key)
	}
	fmt.Fprintf(&b, "\nSource: %s", sourceOf(f))
	return b.String()
}

// sourceOf renders the source fact, unknown included.
func sourceOf(f enrollauth.AdmissionFacts) string {
	if f.Source.IsValid() {
		return f.Source.String()
	}
	return "unknown"
}

// callbackData encodes an answer button's identity — one action byte, the
// boundary, the claim, a digest of the fingerprints — as hex, inside
// Telegram's sixty-four-byte cap: the twenty-six bytes encode to fifty-two
// characters. The digest stands for the fingerprints in the button; the
// standing decision it resolves holds them in full.
func callbackData(approve bool, f enrollauth.AdmissionFacts) string {
	digest := keyDigest(identityOf(f))
	b := make([]byte, 0, 1+1+8+len(digest))
	b = append(b, map[bool]byte{true: 'a', false: 'd'}[approve])
	b = append(b, boundaryByte(f.Boundary))
	b = binary.BigEndian.AppendUint64(b, uint64(f.Claim))
	return hex.EncodeToString(append(b, digest...))
}

// parseCallbackData decodes an answer button's identity.
func parseCallbackData(s string) (bool, askKey, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 1+1+8+sha256.Size/2 {
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
	var boundary enrollauth.Boundary
	switch b[1] {
	case boundaryByte(enrollauth.BoundaryEnrollment):
		boundary = enrollauth.BoundaryEnrollment
	case boundaryByte(enrollauth.BoundaryRegistration):
		boundary = enrollauth.BoundaryRegistration
	default:
		return false, askKey{}, false
	}
	return approve, askKey{
		boundary: boundary,
		claim:    addr.IA(binary.BigEndian.Uint64(b[2:10])),
		digest:   string(b[10:]),
	}, true
}

// keyDigest summarizes the presented fingerprints as the bytes a button
// carries.
func keyDigest(keys string) []byte {
	sum := sha256.Sum256([]byte(keys))
	return sum[:sha256.Size/2]
}

func boundaryByte(b enrollauth.Boundary) byte {
	if b == enrollauth.BoundaryRegistration {
		return 'r'
	}
	return 'e'
}

// call posts one Bot API method and decodes its envelope, the result
// parameter's type naming the method's own.
func call[T any](t *Authorizer, ctx context.Context, method string, req any) (T, error) {
	var zero T
	body, err := json.Marshal(req)
	if err != nil {
		return zero, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/bot%s/%s", t.api, t.token, method), bytes.NewReader(body))
	if err != nil {
		return zero, botAPIError(method, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := t.hc.Do(httpReq)
	if err != nil {
		return zero, botAPIError(method, err)
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

// botAPIError names the method and the failure, never the URL: a
// *url.Error renders the whole request line, and the request line carries
// the bot's token (proposal 0015).
func botAPIError(method string, err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	return fmt.Errorf("%s failed: %w", method, err)
}

// The Bot API's JSON shapes, only as much as the four calls need.

// tgUpdate is one polled update: a pressed answer button or a message.
type tgUpdate struct {
	UpdateID int64            `json:"update_id"`
	Callback *tgCallbackQuery `json:"callback_query,omitempty"`
	Message  *tgMessage       `json:"message,omitempty"`
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

// tgMessage is the message a button rides on or the operator sent.
type tgMessage struct {
	Chat tgChat `json:"chat"`
	Text string `json:"text"`
}

// tgChat names a chat by its id.
type tgChat struct {
	ID int64 `json:"id"`
}

// tgSent is the message a send answers with.
type tgSent struct {
	MessageID int64 `json:"message_id"`
}

// tgSendMessage is one prompted or plain message.
type tgSendMessage struct {
	ChatID      int64         `json:"chat_id"`
	Text        string        `json:"text"`
	ReplyMarkup tgReplyMarkup `json:"reply_markup,omitempty"`
}

// tgReplyMarkup carries a message's inline keyboard; empty on a plain
// reply.
type tgReplyMarkup struct {
	InlineKeyboard [][]tgButton `json:"inline_keyboard,omitempty"`
}

// tgButton is one inline keyboard button.
type tgButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

// tgGetUpdates long-polls for updates from a confirmed offset.
type tgGetUpdates struct {
	Offset  int64 `json:"offset"`
	Timeout int   `json:"timeout"`
}

// tgAnswer acknowledges an answer button.
type tgAnswer struct {
	QueryID string `json:"callback_query_id"`
	Text    string `json:"text"`
}
