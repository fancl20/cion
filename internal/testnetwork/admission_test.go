package testnetwork

import (
	"slices"
	"strings"
	"testing"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/apps/wireguard"
)

// mintedAuthKey asks the bot for an auth key naming the node in the
// configured chat and returns the key its reply carries, the reply naming
// the node.
func mintedAuthKey(t *testing.T, bot *operatorBot, node addr.IA) string {
	t.Helper()
	bot.say("/create_auth_key " + node.String())
	var authKey string
	Poll(t, "the bot to answer with an auth key naming "+node.String(), func() bool {
		bot.mtx.Lock()
		prompts := append([]map[string]any(nil), bot.prompts...)
		bot.mtx.Unlock()
		for _, m := range prompts {
			text, _ := m["text"].(string)
			if !strings.Contains(text, "connects to "+node.String()) {
				continue
			}
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

// registryHosts reads the hosts the core's registry holds.
func registryHosts(t *testing.T, core *assemblyNode) []wireguard.HostEntry {
	t.Helper()
	directory, err := wireguardOf(core).Directory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return directory.Hosts
}

// TestCoordinationAuthKeyJoin is the auth key join's proof: the operator
// approves the leaf's enrollment, asks the bot for a key naming the leaf,
// and hands it to the headless client, which joins unattended onto the
// leaf — the registration presenting the minted key approving on the
// plugin's own records, the note it answers recorded with the entry.
func TestCoordinationAuthKeyJoin(t *testing.T) {
	t.Parallel()
	wpki := packageWebPKI
	place := placeCoordination(t)
	bot := newOperatorBot(t)
	a := coordCore(t, wpki, hostSlot(t), place, func(cfg *services.NodeConfig) {
		cfg.EnrollAuth = "telegram=" + operatorChatToken
		cfg.TelegramAPI = bot.url
	})
	b := coordLeaf(t, wpki, hostSlot(t), a, place, nil)

	// The leaf enrolls on the operator's approval and publishes its slice.
	prompt := -1
	Poll(t, "the leaf's enrollment prompt", func() bool {
		prompt = bot.promptHeaded("CION enrollment request")
		return prompt >= 0
	})
	bot.press(t, prompt, 0)
	Poll(t, "the core's registry holding the leaf's entry", func() bool {
		return holdsHostEndpoint(t, a, b.app.IA())
	})

	// The headless client joins unattended onto the leaf: the auth key
	// approves on the plugin's own records, the login completing with no
	// operator in the loop.
	key := mintedAuthKey(t, bot, b.app.IA())
	ips := hostUp(t, tailnetHost(t, "keyed", place.controlURL, key))
	if len(ips) != 1 || !TailnetRange.Contains(ips[0]) {
		t.Fatalf("the keyed host's addresses = %v", ips)
	}
	if got := ownerOf(t, a, ips[0]); got != b.app.IA() {
		t.Fatalf("the keyed host landed on %s, want the leaf its key names", got)
	}
	// The registry records the approving note beside the entry, and the
	// leaf programs the host.
	hosts := registryHosts(t, a)
	i := slices.IndexFunc(hosts, func(h wireguard.HostEntry) bool { return h.Addr == ips[0] })
	if i < 0 || hosts[i].Note != "telegram auth key" {
		t.Fatalf("the registry holds %+v, want the keyed host with the auth key's note", hosts)
	}
	Poll(t, "the leaf programming the keyed host", func() bool { return programsHost(b, ips[0]) })
}

// TestCoordinationTelegramRefusesBareHost is the refusal at the
// registration boundary: a host presenting no key never joins, and the
// operator's chat shows no prompt for it.
func TestCoordinationTelegramRefusesBareHost(t *testing.T) {
	t.Parallel()
	wpki := packageWebPKI
	place := placeCoordination(t)
	bot := newOperatorBot(t)
	a := coordCore(t, wpki, hostSlot(t), place, func(cfg *services.NodeConfig) {
		cfg.EnrollAuth = "telegram=" + operatorChatToken
		cfg.TelegramAPI = bot.url
	})

	host := tailnetHost(t, "bare", place.controlURL, "")
	// The refusal's budget: a denied registration the client keeps retrying
	// never ends the login itself, so the wait runs its course — the budget
	// only needs to outlast a joining login (observed around three seconds).
	if _, failed := hostUpErr(t, host, TestTimeout/2); !failed {
		t.Fatal("a host presenting no key joined")
	}
	if hosts := registryHosts(t, a); len(hosts) != 0 {
		t.Fatalf("the registry holds %+v, want no host", hosts)
	}
	if got := bot.promptCount(); got != 0 {
		t.Fatalf("the operator's chat shows %d prompts, want none for a host", got)
	}
}

// TestCoordinationCIDRGate is the addressing posture's proof: the listed
// prefixes admit the leaf's enrollment, and a host registering from inside
// them still never joins — the posture admits nodes alone.
func TestCoordinationCIDRGate(t *testing.T) {
	t.Parallel()
	wpki := packageWebPKI
	place := placeCoordination(t)
	a := coordCore(t, wpki, hostSlot(t), place, func(cfg *services.NodeConfig) {
		// The harness's nodes and hosts dial from loopback, which the prefix
		// covers.
		cfg.EnrollAuth = "cidrs=127.0.0.0/8"
	})
	b := coordLeaf(t, wpki, hostSlot(t), a, place, nil)
	Poll(t, "the leaf to enroll from inside the prefix", func() bool {
		return holdsChain(t.Context(), b)
	})

	host := tailnetHost(t, "gated", place.controlURL, "")
	// The gate's budget: a denied registration the client keeps retrying
	// never ends the login itself, so the wait runs its course — the budget
	// only needs to outlast a joining login (observed around three seconds),
	// lest a slow-but-admitted host slip past the negative.
	if _, failed := hostUpErr(t, host, TestTimeout/2); !failed {
		t.Fatal("a host joined under the addressing posture")
	}
	if hosts := registryHosts(t, a); len(hosts) != 0 {
		t.Fatalf("the registry holds %+v, want no host", hosts)
	}
}
