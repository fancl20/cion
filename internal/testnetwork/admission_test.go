package testnetwork

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/fancl20/cion/internal/services"
)

// mintedInvitation asks the bot for an invitation in the configured chat
// and returns the key its reply carries.
func mintedInvitation(t *testing.T, bot *operatorBot) string {
	t.Helper()
	bot.say("invite")
	deadline := time.Now().Add(TestTimeout)
	for time.Now().Before(deadline) {
		bot.mtx.Lock()
		prompts := append([]map[string]any(nil), bot.prompts...)
		bot.mtx.Unlock()
		for _, m := range prompts {
			text, _ := m["text"].(string)
			for _, line := range strings.Split(text, "\n") {
				if strings.HasPrefix(line, "cion-") {
					return line
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the bot never answered with an invitation")
	return ""
}

// TestCoordinationInvitationJoin is the invitation join's proof: the
// operator asks the bot for a key in the configured chat, hands it to the
// headless client, and the client joins unattended — the registration
// presenting the minted key approving on the plugin's own records, the
// note it answers recorded with the entry.
func TestCoordinationInvitationJoin(t *testing.T) {
	t.Parallel()
	wpki := packageWebPKI
	place := placeCoordination(t)
	bot := newOperatorBot(t)
	a := coordCore(t, wpki, hostSlot(t), place, func(cfg *services.NodeConfig) {
		cfg.EnrollAuth = "telegram=" + operatorChatToken
		cfg.TelegramAPI = bot.url
	})
	_ = coordLeaf(t, wpki, hostSlot(t), a, place, nil)

	key := mintedInvitation(t, bot)

	// The headless client joins unattended: the invitation approves on the
	// plugin's own records, the login completing with no operator in the
	// loop.
	host := tailnetHost(t, "invited", place.controlURL, key)
	ips := hostUp(t, host)
	if len(ips) != 1 || !TailnetRange.Contains(ips[0]) {
		t.Fatalf("the invited host's addresses = %v", ips)
	}
	// The registry records the approving note beside the entry.
	Poll(t, "the entry carrying the invitation's note", func() bool {
		hosts := wireguardOf(a).HostPeers()
		return len(hosts) == 1 && hosts[0].Note == "telegram invitation"
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
		ctx, cancel := context.WithTimeout(context.Background(), RestartTimeout)
		defer cancel()
		status, err := host.Up(ctx)
		if err != nil {
			done <- result{err: true}
			return
		}
		done <- result{ips: status.TailscaleIPs}
	}()

	// The prompt lands in the configured chat; the operator approves.
	Poll(t, "the registration prompt", func() bool { return bot.promptCount() > 0 })
	bot.press(t, 0, 0)
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
