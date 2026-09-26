// Package enrollauth is the admission policy of ADR-0010, generalized by
// ADR-0011: the implementations the --enroll-auth run argument selects,
// living beside the core they gate — the package imports the control plane's
// seam and is imported by the node assembly alone, never the reverse. The
// one authorizer a selection loads answers both boundaries the seam serves:
// the CIDR posture admits joiners by addressing, nodes and hosts alike; the
// Telegram posture admits them one by one from an operator's phone, with
// invitations a headless client can carry.
package enrollauth

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/fancl20/cion/pkg/controlplane"
)

// Load parses a --enroll-auth spec (ADR-0010) — "method=spec" — and builds
// the authorizer it names: "cidrs" with a comma-separated prefix list,
// "telegram" with <chat>:<token>, the split on the first colon so the
// token's own colon survives intact. The run function launches the selected
// method's own loops — the Telegram authorizer's poll — under the caller's
// supervision; nil when the method has none. The spec parses here once, so
// a malformed one fails the boot, not the first joiner. Exactly one method
// loads: unset is open, the zero-conf default, and the single-value shape
// leaves combination a later change that touches no interface.
func Load(spec string, opts LoadOptions) (
	controlplane.AdmissionAuthorizer,
	func(context.Context),
	error,
) {

	method, rest, found := strings.Cut(spec, "=")
	if !found {
		return nil, nil, fmt.Errorf("expected method=spec in %q", spec)
	}
	switch method {
	case "cidrs":
		cidrs, err := NewCIDR(rest)
		if err != nil {
			return nil, nil, err
		}
		return cidrs, nil, nil
	case "telegram":
		chat, token, found := strings.Cut(rest, ":")
		if !found {
			return nil, nil, fmt.Errorf("expected <chat>:<token> in %q", rest)
		}
		id, err := strconv.ParseInt(chat, 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing chat %q: %w", chat, err)
		}
		if token == "" {
			return nil, nil, fmt.Errorf("empty bot token")
		}
		telegram, err := NewTelegram(TelegramConfig{
			API:   opts.TelegramAPI,
			Chat:  id,
			Token: token,
			State: opts.State,
		})
		if err != nil {
			return nil, nil, err
		}
		return telegram, telegram.Run, nil
	default:
		return nil, nil, fmt.Errorf("unknown enroll-auth method %q", method)
	}
}

// LoadOptions carries what the assembly knows beyond the spec itself.
type LoadOptions struct {
	// TelegramAPI overrides the Bot API's base URL for the telegram method —
	// the public one when empty. The integration tests point it at their
	// local double.
	TelegramAPI string
	// State is the core's state directory, the persistent home of the
	// Telegram method's unspent invitations; the other methods hold no
	// state of their own.
	State string
}
