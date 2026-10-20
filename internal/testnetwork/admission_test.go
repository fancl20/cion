package testnetwork

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/fancl20/cion/internal/services"
)

// mintedAuthKey asks the bot for an auth key in the configured chat
// and returns the key its reply carries.
func mintedAuthKey(t *testing.T, bot *operatorBot) string {
	t.Helper()
	bot.say("/create_auth_key")
	var authKey string
	Poll(t, "the bot to answer with an auth key", func() bool {
		bot.mtx.Lock()
		prompts := append([]map[string]any(nil), bot.prompts...)
		bot.mtx.Unlock()
		for _, m := range prompts {
			text, _ := m["text"].(string)
			for line := range strings.SplitSeq(text, "\n") {
				if strings.HasPrefix(line, "cion-") {
					authKey = line
					return true
				}
			}
		}
		return false
	})
	return authKey
}

// TestCoordinationAuthKeyJoin is the auth key join's proof: the
// operator asks the bot for a key in the configured chat, hands it to the
// headless client, and the client joins unattended — the registration
// presenting the minted key approving on the plugin's own records, the
// note it answers recorded with the entry.
func TestCoordinationAuthKeyJoin(t *testing.T) {
	t.Parallel()
	wpki := packageWebPKI
	place := placeCoordination(t)
	bot := newOperatorBot(t)
	a := coordCore(t, wpki, hostSlot(t), place, func(cfg *services.NodeConfig) {
		cfg.EnrollAuth = "telegram=" + operatorChatToken
		cfg.TelegramAPI = bot.url
	})
	_ = coordLeaf(t, wpki, hostSlot(t), a, place, nil)

	key := mintedAuthKey(t, bot)

	// The headless client joins unattended: the auth key approves on the
	// plugin's own records, the login completing with no operator in the
	// loop.
	host := tailnetHost(t, "keyed", place.controlURL, key)
	ips := hostUp(t, host)
	if len(ips) != 1 || !TailnetRange.Contains(ips[0]) {
		t.Fatalf("the keyed host's addresses = %v", ips)
	}
	// The registry records the approving note beside the entry.
	Poll(t, "the entry carrying the auth key's note", func() bool {
		hosts := wireguardOf(a).HostPeers()
		return len(hosts) == 1 && hosts[0].Note == "telegram auth key"
	})
}

// TestCoordinationTelegramPromptJoin is the prompted join at the
// registration boundary: a bare host pends behind a prompt until the
// operator presses approve, the login completing on the client's own
// retry.
func TestCoordinationTelegramPromptJoin(t *testing.T) {
	t.Parallel()
	wpki := packageWebPKI
	place := placeCoordination(t)
	bot := newOperatorBot(t)
	a := coordCore(t, wpki, hostSlot(t), place, func(cfg *services.NodeConfig) {
		cfg.EnrollAuth = "telegram=" + operatorChatToken
		cfg.TelegramAPI = bot.url
	})
	_ = coordLeaf(t, wpki, hostSlot(t), a, place, nil)

	host := tailnetHost(t, "prompted", place.controlURL, "")
	type result struct {
		ips []netip.Addr
		err bool
	}
	done := make(chan result, 1)
	go func() {
		// The login's budget is the operator's reaction time plus the
		// client's own retry backoff, the restart lab's patience rather
		// than the plain test timeout.
		ctx, cancel := context.WithTimeout(t.Context(), RestartTimeout)
		defer cancel()
		status, err := host.Up(ctx)
		if err != nil {
			done <- result{err: true}
			return
		}
		done <- result{ips: status.TailscaleIPs}
	}()

	// The prompt lands in the configured chat beside the leaf's enrollment
	// prompt, the two in either order; the operator approves the
	// registration.
	prompt := -1
	Poll(t, "the registration prompt", func() bool {
		prompt = bot.promptHeaded("CION registration request")
		return prompt >= 0
	})
	bot.press(t, prompt, 0)
	select {
	case got := <-done:
		if got.err || len(got.ips) != 1 || !TailnetRange.Contains(got.ips[0]) {
			t.Fatalf("the approved host's login = %+v", got)
		}
	case <-time.After(RestartTimeout):
		t.Fatal("the approval never completed the login")
	}
}

// TestCoordinationCIDRGate is the addressing posture's negative: a
// registration whose source falls outside the listed prefixes never joins.
func TestCoordinationCIDRGate(t *testing.T) {
	t.Parallel()
	wpki := packageWebPKI
	place := placeCoordination(t)
	a := coordCore(t, wpki, hostSlot(t), place, func(cfg *services.NodeConfig) {
		// The harness's hosts dial from 127.0.0.1; the prefix refuses all
		// loopback.
		cfg.EnrollAuth = "cidrs=192.0.2.0/24"
	})
	_ = coordLeaf(t, wpki, hostSlot(t), a, place, nil)

	host := tailnetHost(t, "gated", place.controlURL, "")
	// The gate's budget: a denied registration the client keeps retrying
	// never ends the login itself, so the wait runs its course — the budget
	// only needs to outlast a joining login (observed around three seconds),
	// lest a slow-but-admitted host slip past the negative.
	if _, failed := hostUpErr(t, host, TestTimeout/2); !failed {
		t.Fatal("a host outside the listed prefixes joined")
	}
	if hosts := wireguardOf(a).HostPeers(); len(hosts) != 0 {
		t.Fatalf("the gate recorded %d hosts, want none", len(hosts))
	}
}
