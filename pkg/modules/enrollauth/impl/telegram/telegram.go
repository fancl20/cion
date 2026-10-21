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

	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/libs/statefile"
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

// authKeyPrefix marks a minted auth key among the credentials a
// registration may carry; authKeyBytes is the random body's length.
const (
	authKeyPrefix = "cion-"
	authKeyBytes  = 16
)

// The notes the registry records beside an entry the plugin allowed: by
// the operator's press, or by an auth key's presentation.
const (
	operatorNote = "telegram operator"
	authKeyNote  = "telegram auth key"
)

// authKeysFile holds the unspent auth keys beneath the core's state.
const authKeysFile = "telegram-auth-keys.json"

// Config configures the Telegram authorizer.
type Config struct {
	// API is the Bot API's base URL; empty is the public one.
	API string
	// Chat is the chat the prompts go to and the only one whose answers
	// count — and the only one the operator can mint or retire auth keys
	// from.
	Chat int64
	// Token is the bot's token. It rides the run argument and so the
	// process list — an accepted consequence of argument-driven
	// configuration, the file indirection deliberately not built.
	Token string
	// State is the core's state directory: the unspent auth keys'
	// persistent home, so an auth key survives a restart while the
	// transient asks stay in memory.
	State string
	// Window overrides how long one prompt's verdict stands; zero uses the
	// default.
	Window time.Duration
}

// Authorizer is the admission authorizer of the operator's phone: per new
// identity — the boundary, the claim, and the presented keys' fingerprints
// keyed together — it prompts the configured chat over the Bot API with the
// facts and an approve and a deny button, and answers on the long-polled
// callbacks, one prompt per identity inside a decision window — a decided
// prompt rewritten to its verdict with its buttons gone. The auth key
// reverses the flow: the operator asks the bot for a key in the configured
// chat, hands it to the headless client, and a registration presenting a key
// the plugin minted and has not spent approves on the plugin's own records and
// spends it, the approval standing for the presenting machine for a window,
// as a press's does; a spent or unknown key is a bare joiner's, prompted as
// ever — a stale auth key fails toward the human, not closed. It speaks the
// API directly over net/http — no SDK, for a vendored tree prices every
// dependency, and the handful of calls this needs are plain HTTPS and JSON.
// The prompts' decisions live in memory: a restart forgets pending and denied
// entries and a join still in flight asks again, while the unspent auth keys
// persist in the state directory.
type Authorizer struct {
	api    string
	chat   int64
	token  string
	state  string
	window time.Duration
	hc     *http.Client

	// mtx guards asks and authKeys, shared by the admission handlers and
	// the poll loop.
	mtx      sync.Mutex
	asks     map[askKey]*decision
	authKeys map[string]struct{}
}

// askKey names one identity: the boundary asking, the exchange's claim,
// and a digest of the presented keys' fingerprints, so two strangers
// claiming one name present two asks and the operator approves at most one
// — the name-taken check settles the loser on its next retry. The digest
// is what an answer button carries; the standing decision it resolves
// holds the fingerprints in full.
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
	// keyed marks an approval an auth key's presentation made rather than
	// the operator's press.
	keyed bool
}

// New builds the authorizer; Run launches its poll loop. Unspent auth keys
// load from the state directory when its file exists.
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
		api:      api,
		chat:     cfg.Chat,
		token:    cfg.Token,
		state:    cfg.State,
		window:   window,
		hc:       &http.Client{},
		asks:     make(map[askKey]*decision),
		authKeys: make(map[string]struct{}),
	}
	if err := t.loadAuthKeys(); err != nil {
		return nil, err
	}
	return t, nil
}

// Authorize answers one admission exchange. A registration presenting a
// credential the plugin minted and has not spent approves and spends it,
// the approval standing for the presenting machine for the window: the
// caller may refuse an approved registration — no slice yet to allocate in
// — and the machine's retry rides the approval rather than the spent key. A
// standing decision returns for its window's remainder, and the first ask —
// or the first past the window — sends the chat one prompt and pends. A
// prompt that cannot be sent denies: with the API unreachable admission
// fails closed, safe, but unavailable until it returns.
func (t *Authorizer) Authorize(
	ctx context.Context,
	f enrollauth.AdmissionFacts,
) enrollauth.AdmissionAnswer {

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
	if f.Boundary == enrollauth.BoundaryRegistration && f.Credential != "" &&
		t.spendAuthKeyLocked(f.Credential) {

		t.asks[key] = &decision{
			admission: enrollauth.AdmissionAllow,
			label:     strings.Join(f.Keys, ","),
			expires:   now.Add(t.window),
			keyed:     true,
		}
		t.mtx.Unlock()
		return enrollauth.AdmissionAnswer{
			Admission: enrollauth.AdmissionAllow,
			Note:      authKeyNote,
		}
	}
	if d, ok := t.asks[key]; ok && now.Before(d.expires) {
		answer := enrollauth.AdmissionAnswer{Admission: d.admission, Note: d.note()}
		t.mtx.Unlock()
		return answer
	}
	// The ask pends before its prompt goes out: the chat shows the prompt
	// before the send returns, and a press must find the ask it answers.
	pending := &decision{
		admission: enrollauth.AdmissionPending,
		label:     strings.Join(f.Keys, ","),
		expires:   now.Add(t.window),
	}
	t.asks[key] = pending
	t.mtx.Unlock()
	if err := t.sendPrompt(ctx, f); err != nil {
		slog.Warn("Sending the admission prompt; denying",
			"boundary", f.Boundary, "claim", f.Claim, "source", f.Source, "err", err)
		// The failed send withdraws the ask, so the next one prompts again,
		// unless the operator already answered a prompt that did show.
		t.mtx.Lock()
		if t.asks[key] == pending && pending.admission == enrollauth.AdmissionPending {
			delete(t.asks, key)
		}
		t.mtx.Unlock()
		return enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionDeny}
	}
	return enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionPending}
}

// note is the standing decision's own account of itself, the string the
// registry records beside an entry the decision approved.
func (d *decision) note() string {
	switch {
	case d.admission != enrollauth.AdmissionAllow:
		return ""
	case d.keyed:
		return authKeyNote
	default:
		return operatorNote
	}
}

// Run receives the operator's chat until the context is canceled: it offers
// the console's commands once, then one getUpdates long poll after another,
// under the caller's supervision, each pass sweeping the decisions whose
// window has passed and answering the buttons pressed and the messages sent.
func (t *Authorizer) Run(ctx context.Context) {
	t.offerCommands(ctx)
	var offset int64
	for ctx.Err() == nil {
		updates, err := t.getUpdates(ctx, offset)
		if err != nil {
			if ctx.Err() == nil {
				slog.Warn("Polling the Bot API", "err", err)
				if !loops.Sleep(ctx, pollRetry) {
					return
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

// sweep drops the decisions whose window has passed: a stranger's persistent
// identities cost their prompts and nothing after.
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

// offerCommands registers the console's two commands in the clients' menus,
// so the operator types them offered rather than from memory. A failure to
// register takes no command away: they answer unregistered, merely unoffered.
func (t *Authorizer) offerCommands(ctx context.Context) {
	actx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	if _, err := call[bool](t, actx, "setMyCommands", tgSetCommands{
		Commands: []tgCommand{
			{Command: "create_auth_key", Description: "Mint a one-use auth key"},
			{Command: "delete_auth_key", Description: "Retire an unspent auth key"},
		},
	}); err != nil {
		slog.Warn("Registering the console's commands", "err", err)
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
// strong no-prompt guarantee being the registry's, not the map's. The decided
// prompt is rewritten to its verdict without its buttons, so the chat shows
// the outcome and offers nothing to press again.
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
	t.settle(ctx, cb.Message, approve)
}

// converse handles the operator's own messages — the auth key flow's mint
// and retire, the two slash commands the console offers. Only the
// configured chat's count: it is the one chat the prompts went to, and the
// one channel this plugin treats as its console.
func (t *Authorizer) converse(ctx context.Context, msg *tgMessage) {
	if msg == nil {
		return // an update that carries no message
	}
	if msg.Chat.ID != t.chat {
		slog.Warn("Ignoring a message from another chat", "chat", msg.Chat.ID)
		return
	}
	cmd, arg := commandOf(strings.TrimSpace(msg.Text))
	switch {
	case cmd == "/create_auth_key":
		key := t.mintAuthKey()
		slog.Info("Auth key minted", "chat", t.chat)
		t.reply(ctx, fmt.Sprintf(
			"Auth key (one use):\n%s\nRetire it with /delete_auth_key <key>.", key))
	case cmd == "/delete_auth_key" && arg != "":
		if t.retireAuthKey(arg) {
			slog.Info("Auth key retired", "chat", t.chat)
			t.reply(ctx, "Auth key retired.")
		} else {
			t.reply(ctx, "No unspent auth key matched.")
		}
	default:
		t.reply(ctx, "Send /create_auth_key to mint an auth key, or /delete_auth_key <key> to retire one.")
	}
}

// commandOf splits one console message into its command and the argument
// after it: the command lowercased and its @addressed suffix dropped, both
// empty when the message is no command.
func commandOf(text string) (string, string) {
	if !strings.HasPrefix(text, "/") {
		return "", ""
	}
	cmd, arg, _ := strings.Cut(text, " ")
	if at := strings.IndexByte(cmd, '@'); at >= 0 {
		cmd = cmd[:at]
	}
	return strings.ToLower(cmd), strings.TrimSpace(arg)
}

// mintAuthKey creates one unspent auth key and persists the set.
func (t *Authorizer) mintAuthKey() string {
	raw := make([]byte, authKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		// crypto/rand's failure is the process's own catastrophe; an empty
		// auth key can never be presented and so never admits.
		slog.Error("Minting an auth key", "err", err)
		return authKeyPrefix + strings.Repeat("0", 2*authKeyBytes)
	}
	key := authKeyPrefix + hex.EncodeToString(raw)
	t.mtx.Lock()
	t.authKeys[key] = struct{}{}
	err := t.persistAuthKeysLocked()
	t.mtx.Unlock()
	if err != nil {
		slog.Warn("Persisting the auth keys", "err", err)
	}
	return key
}

// spendAuthKeyLocked removes one unspent auth key and persists the set,
// reporting whether the credential spent; the caller holds the mutex.
func (t *Authorizer) spendAuthKeyLocked(key string) bool {
	if _, ok := t.authKeys[key]; !ok {
		return false
	}
	delete(t.authKeys, key)
	if err := t.persistAuthKeysLocked(); err != nil {
		slog.Warn("Persisting the auth keys", "err", err)
	}
	return true
}

// retireAuthKey removes one unspent auth key the retire command named and
// persists the set, reporting whether the command named one.
func (t *Authorizer) retireAuthKey(text string) bool {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	return t.spendAuthKeyLocked(text)
}

// loadAuthKeys reads the persisted unspent auth keys. A missing file is a
// fresh start; a present one the auth keys an operator minted before the
// restart.
func (t *Authorizer) loadAuthKeys() error {
	if t.state == "" {
		return errors.New("no state directory configured for the auth keys")
	}
	raw, err := os.ReadFile(t.authKeysPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("reading the auth keys: %w", err)
	}
	var keys []string
	if err := json.Unmarshal(raw, &keys); err != nil {
		return fmt.Errorf("parsing the auth keys: %w", err)
	}
	for _, key := range keys {
		t.authKeys[key] = struct{}{}
	}
	return nil
}

// persistAuthKeysLocked writes the unspent auth keys back, whole; the
// caller holds the mutex.
func (t *Authorizer) persistAuthKeysLocked() error {
	keys := make([]string, 0, len(t.authKeys))
	for key := range t.authKeys {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	raw, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	if err := statefile.Write(t.authKeysPath(), raw); err != nil {
		return fmt.Errorf("writing the auth keys: %w", err)
	}
	return nil
}

func (t *Authorizer) authKeysPath() string {
	return filepath.Join(t.state, "enrollauth", authKeysFile)
}

// answer acknowledges an answer button on the operator's phone.
func (t *Authorizer) answer(ctx context.Context, id, text string) {
	actx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	if _, err := call[bool](t, actx, "answerCallbackQuery", tgAnswer{
		QueryID: id,
		Text:    text,
	}); err != nil {
		slog.Debug("Acknowledging an admission answer", "err", err)
	}
}

// reply sends the chat one plain message — the auth key flow's side of
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

// settle rewrites the decided prompt: the verdict joins the text and the
// buttons leave with it. A failed edit changes no decision — the press's own
// acknowledgement already told the operator — so it is logged and lived with.
func (t *Authorizer) settle(ctx context.Context, msg *tgMessage, approve bool) {
	if msg == nil {
		return // an answer with no message to rewrite
	}
	verdict := "Denied"
	if approve {
		verdict = "Approved"
	}
	actx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	if _, err := call[tgSent](t, actx, "editMessageText", tgEditMessage{
		ChatID:    msg.Chat.ID,
		MessageID: msg.MessageID,
		Text:      msg.Text + "\n" + verdict,
	}); err != nil {
		slog.Debug("Rewriting the decided prompt", "err", err)
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
// registration's offered keys, the voting submission's added keys, the
// source beside them.
func promptText(f enrollauth.AdmissionFacts) string {
	var b strings.Builder
	switch f.Boundary {
	case enrollauth.BoundaryRegistration:
		b.WriteString("CION registration request")
	case enrollauth.BoundaryVoting:
		b.WriteString("CION voting power request")
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

// botAPIError names the method and the failure, never the URL: a *url.Error
// renders the whole request line, and the request line carries the bot's
// token.
func botAPIError(method string, err error) error {
	if urlErr, ok := errors.AsType[*url.Error](err); ok {
		err = urlErr.Err
	}
	return fmt.Errorf("%s failed: %w", method, err)
}

// The Bot API's JSON shapes, only as much as the calls need.

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

// tgMessage is the message a button rides on or the operator sent; the id
// names the message a decided prompt rewrites.
type tgMessage struct {
	MessageID int64  `json:"message_id"`
	Chat      tgChat `json:"chat"`
	Text      string `json:"text"`
}

// tgChat names a chat by its id.
type tgChat struct {
	ID int64 `json:"id"`
}

// tgSent is the message a send answers with.
type tgSent struct {
	MessageID int64 `json:"message_id"`
}

// tgSendMessage is one prompted or plain message; the markup omits on a
// plain reply, which carries no keyboard.
type tgSendMessage struct {
	ChatID      int64         `json:"chat_id"`
	Text        string        `json:"text"`
	ReplyMarkup tgReplyMarkup `json:"reply_markup,omitzero"`
}

// tgEditMessage rewrites one sent message; a decided prompt's edit carries
// no markup, for the keyboard left out is the keyboard removed.
type tgEditMessage struct {
	ChatID    int64  `json:"chat_id"`
	MessageID int64  `json:"message_id"`
	Text      string `json:"text"`
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

// tgSetCommands registers the commands the clients' menus offer.
type tgSetCommands struct {
	Commands []tgCommand `json:"commands"`
}

// tgCommand is one offered command and its menu description.
type tgCommand struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}
