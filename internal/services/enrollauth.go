package services

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/fancl20/cion/pkg/modules/enrollauth"
	"github.com/fancl20/cion/pkg/modules/enrollauth/impl/cidr"
	"github.com/fancl20/cion/pkg/modules/enrollauth/impl/telegram"
)

// loadEnrollAuth builds the authorizer a --trust.enroll-auth spec names —
// "method=spec": "cidrs" with a comma-separated prefix list, "telegram"
// with <chat>:<token>, the split on the first colon so the token's own
// colon survives intact. The assembly imports the implementation the spec
// names directly. The run function launches the selected method's own
// loops — the Telegram authorizer's poll — under the caller's supervision;
// nil when the method has none. The spec parses here once, so a malformed
// one fails the boot, not the first joiner.
func loadEnrollAuth(spec string, api, state string) (
	enrollauth.AdmissionAuthorizer,
	func(context.Context),
	error,
) {

	method, rest, found := strings.Cut(spec, "=")
	if !found {
		return nil, nil, fmt.Errorf("expected method=spec in %q", spec)
	}
	switch method {
	case "cidrs":
		auth, err := cidr.New(rest)
		if err != nil {
			return nil, nil, err
		}
		return auth, nil, nil
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
		auth, err := telegram.New(telegram.Config{
			API:   api,
			Chat:  id,
			Token: token,
			State: state,
		})
		if err != nil {
			return nil, nil, err
		}
		return auth, auth.Run, nil
	default:
		return nil, nil, fmt.Errorf("unknown enroll-auth method %q", method)
	}
}
