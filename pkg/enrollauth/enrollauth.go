// Package enrollauth is the enrollment policy of ADR-0010: the
// implementations the --enroll-auth run argument selects, living beside the
// core they gate — the package imports the control plane's seam and is
// imported by the node assembly alone, never the reverse. The CIDR
// authorizer admits joiners by addressing; the Telegram authorizer admits
// them one by one from an operator's phone.
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
	controlplane.EnrollmentAuthorizer,
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
		telegram := NewTelegram(TelegramConfig{
			API:   opts.TelegramAPI,
			Chat:  id,
			Token: token,
		})
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
}
