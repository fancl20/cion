package voting

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	trustbbolt "github.com/fancl20/cion/pkg/modules/trustdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/peeria"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
	votingv1 "github.com/fancl20/cion/proto/voting/v1"
	votingv1connect "github.com/fancl20/cion/proto/voting/v1/votingv1connect"
)

// coreIA and joinerIA name the fixture's two sides.
var (
	coreIA   = addr.MustIAFrom(20, 0xff0000000001)
	joinerIA = addr.MustIAFrom(20, 0xff0000000f01)
)

// decideFunc adapts a function to the Decider interface.
type decideFunc func(context.Context, addr.IA, cppki.SignedTRC) (cppki.SignedTRC, error)

func (f decideFunc) DecideTRC(ctx context.Context, presenter addr.IA,
	trc cppki.SignedTRC) (cppki.SignedTRC, error) {

	return f(ctx, presenter, trc)
}

// newTestApp builds the application over a captured mount, with the decision
// the test provides.
func newTestApp(t *testing.T, decide Decider) (http.Handler, string) {
	t.Helper()
	var pattern string
	var handler http.Handler
	_, err := New(Config{
		IA:     coreIA,
		Decide: decide,
		MountControlEndpoint: func(p string, h http.Handler) error {
			pattern, handler = p, h
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, pattern
}

// presenterContext carries the verified peer the channel would have; the
// connect request's context flows to the handler, where the application
// reads it.
func presenterContext(ia addr.IA) context.Context {
	return context.WithValue(context.Background(), peeria.AuthenticatedIAContextKey(), ia)
}

// clientOf returns an HTTP client whose every request the handler serves —
// the connect machinery's round trip with no network beneath it.
func clientOf(h http.Handler) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Result(), nil
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// submit calls the application's RPC over the handler.
func submit(
	t *testing.T,
	h http.Handler,
	ctx context.Context,
	trc cppki.SignedTRC,
) (cppki.SignedTRC, error) {

	t.Helper()
	clt := votingv1connect.NewVotingServiceClient(clientOf(h), "https://core")
	resp, err := clt.Submit(ctx, connect.NewRequest(&votingv1.SubmitRequest{Trc: trc.Raw}))
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	return cppki.DecodeSignedTRC(resp.Msg.Trc)
}

// fixtureTRC returns a decodable signed TRC, the artifact's shape alone
// mattering to these tests.
func fixtureTRC(t *testing.T) cppki.SignedTRC {
	t.Helper()
	dir := t.TempDir()
	db, err := trustbbolt.New(filepath.Join(dir, "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	keys, err := trust.LoadOrCreateCoreKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	trc, err := trust.Genesis(context.Background(), db, coreIA, keys)
	if err != nil {
		t.Fatal(err)
	}
	return trc
}

// TestSubmitHandsToDecision checks the application's one job: a submission
// from a verified presenter is handed to the control plane's decision with
// the channel's fact, and the completed TRC the decision returned is answered
// in its own bytes.
func TestSubmitHandsToDecision(t *testing.T) {
	trc := fixtureTRC(t)
	var gotPresenter addr.IA
	var gotTRC cppki.SignedTRC
	handler, pattern := newTestApp(t, decideFunc(
		func(ctx context.Context, presenter addr.IA,
			submitted cppki.SignedTRC) (cppki.SignedTRC, error) {

			gotPresenter, gotTRC = presenter, submitted
			return trc, nil
		}))

	got, err := submit(t, handler, presenterContext(joinerIA), trc)
	if err != nil {
		t.Fatal(err)
	}
	if !gotPresenter.Equal(joinerIA) {
		t.Errorf("the decision's presenter = %v, want the channel's %v",
			gotPresenter, joinerIA)
	}
	if string(gotTRC.Raw) != string(trc.Raw) {
		t.Error("the decision's TRC differs from the submitted one")
	}
	if string(got.Raw) != string(trc.Raw) {
		t.Error("the response carries bytes other than the decision's")
	}
	if want := "/" + votingv1connect.VotingServiceName + "/"; pattern != want {
		t.Errorf("the mounted pattern = %q, want %q", pattern, want)
	}
}

// TestSubmitRefusals checks the application's doors: no verified presenter,
// no TRC, a decision that refuses, and a node whose control plane decides
// nothing.
func TestSubmitRefusals(t *testing.T) {
	trc := fixtureTRC(t)
	cases := []struct {
		name   string
		ctx    context.Context
		decide Decider
		trc    cppki.SignedTRC
		want   connect.Code
	}{
		{
			"no verified presenter", context.Background(), nil, trc,
			connect.CodePermissionDenied,
		},
		{
			"no TRC", presenterContext(joinerIA), nil, cppki.SignedTRC{},
			connect.CodeInvalidArgument,
		},
		{
			"a refusing decision", presenterContext(joinerIA),
			decideFunc(func(context.Context, addr.IA, cppki.SignedTRC) (cppki.SignedTRC, error) {
				return cppki.SignedTRC{}, errors.New("refused")
			}), trc, connect.CodeFailedPrecondition,
		},
		{
			"no decision on this node", presenterContext(joinerIA), nil, trc,
			connect.CodeUnimplemented,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler, _ := newTestApp(t, tc.decide)
			_, err := submit(t, handler, tc.ctx, tc.trc)
			if connect.CodeOf(err) != tc.want {
				t.Errorf("the refusal = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestSubmitterReportsAbsentApp checks the submitter's terminal mapping: an
// endpoint that answers with no voting application mounted — the route
// refused, not silent — is trust.ErrNoVotingApp; an endpoint that serves the
// application answers with the decision's TRC; and a core the route cannot
// resolve yet is a retry, not a verdict.
func TestSubmitterReportsAbsentApp(t *testing.T) {
	trc := fixtureTRC(t)

	absent := NewSubmitter(clientOf(http.NotFoundHandler()), func() *scion.Addr {
		return &scion.Addr{IA: coreIA}
	})
	if _, err := absent.SubmitTRC(context.Background(), trc); !errors.Is(err, trust.ErrNoVotingApp) {
		t.Fatalf("the absent application's error = %v, want ErrNoVotingApp", err)
	}

	handler, _ := newTestApp(t, decideFunc(
		func(context.Context, addr.IA, cppki.SignedTRC) (cppki.SignedTRC, error) {
			return trc, nil
		}))
	serving := NewSubmitter(clientOf(handler), func() *scion.Addr {
		return &scion.Addr{IA: coreIA}
	})
	got, err := serving.SubmitTRC(presenterContext(joinerIA), trc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Raw) != string(trc.Raw) {
		t.Error("the submitter's answer differs from the decision's")
	}

	dark := NewSubmitter(clientOf(handler), func() *scion.Addr { return nil })
	if _, err := dark.SubmitTRC(context.Background(), trc); err == nil ||
		errors.Is(err, trust.ErrNoVotingApp) {

		t.Errorf("the unresolved route's error = %v, want an ordinary retry failure", err)
	}
}
