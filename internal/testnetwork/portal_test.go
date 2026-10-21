package testnetwork

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"strings"
	"testing"

	"github.com/fancl20/cion/internal/passkeytest"
	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/apps/portal"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
)

// portalClient is the operator's browser on the founder's console: the
// lab's CA trusted, the core's domain dialed at the harness's HTTPS
// placement, and the session's cookies kept.
type portalClient struct {
	t      *testing.T
	origin string
	client *http.Client
}

// newPortalClient opens a browser on the console the placement serves.
func newPortalClient(t *testing.T, wpki *webpkitest.CA, place coordinationPlacement) *portalClient {
	t.Helper()
	_, port, err := net.SplitHostPort(place.addr)
	if err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: wpki.Pool, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, place.addr)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &portalClient{
		t:      t,
		origin: "https://" + net.JoinHostPort(webpkitest.Domain, port),
		client: &http.Client{Transport: transport, Jar: jar},
	}
}

// expect sends one request — raw bytes as they are, any other body as its
// JSON — and fails the test unless it answers the status, answering the
// response's body.
func (c *portalClient) expect(status int, method, path string, body any) []byte {
	c.t.Helper()
	var reader io.Reader = http.NoBody
	switch b := body.(type) {
	case nil:
	case []byte:
		reader = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			c.t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(c.t.Context(), method, c.origin+path, reader)
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		c.t.Fatal(err)
	}
	if resp.StatusCode != status {
		c.t.Fatalf("%s %s = %d %s, want %d", method, path, resp.StatusCode, raw, status)
	}
	return raw
}

// portalAsk, portalNode, and portalHost are the console's answers as the lab
// reads them.
type portalAsk struct {
	ID    string `json:"id"`
	Claim string `json:"claim"`
	State string `json:"state"`
}

type portalNode struct {
	IA       string `json:"ia"`
	Endpoint string `json:"endpoint"`
}

type portalHost struct {
	Addr      string `json:"addr"`
	NodeKey   string `json:"nodeKey"`
	Owner     string `json:"owner"`
	Endpoint  string `json:"endpoint"`
	Note      string `json:"note"`
	Connected bool   `json:"connected"`
}

// nodes reads the console's nodes beside their asks.
func (c *portalClient) nodes() ([]portalNode, []portalAsk) {
	c.t.Helper()
	var v struct {
		Nodes []portalNode `json:"nodes"`
		Asks  []portalAsk  `json:"asks"`
	}
	if err := json.Unmarshal(c.expect(http.StatusOK, http.MethodGet, "/admin/api/nodes", nil), &v); err != nil {
		c.t.Fatal(err)
	}
	return v.Nodes, v.Asks
}

// hosts reads the console's hosts.
func (c *portalClient) hosts() []portalHost {
	c.t.Helper()
	var v struct {
		Hosts []portalHost `json:"hosts"`
	}
	if err := json.Unmarshal(c.expect(http.StatusOK, http.MethodGet, "/admin/api/hosts", nil), &v); err != nil {
		c.t.Fatal(err)
	}
	return v.Hosts
}

// programsHost reports whether the node's host device holds the address.
func programsHost(n *assemblyNode, ip netip.Addr) bool {
	for _, host := range wireguardOf(n).HostPeers() {
		if host.Addr == ip {
			return true
		}
	}
	return false
}

// TestPortalConsole is the console's proof on a running network: the
// operator registers the first passkey with the token the founder printed;
// a joining node's enrollment pends in the console and completes on its
// approval; a host joins unattended with an auth key the console minted
// naming the leaf, landing on the leaf and listed with the key's note, the
// leaf's host endpoint, and its presence; and its release closes its
// tunnel, the leaf dropping the peer.
func TestPortalConsole(t *testing.T) {
	t.Parallel()
	wpki := packageWebPKI
	place := placeCoordination(t)
	a := coordCore(t, wpki, hostSlot(t), place, func(cfg *services.NodeConfig) {
		cfg.EnrollAuth = "portal"
	})
	b := coordLeaf(t, wpki, hostSlot(t), a, place, nil)

	console := newPortalClient(t, wpki, place)
	portalApp := a.app.Application("portal").(*portal.App)
	_, token, found := strings.Cut(portalApp.SetupLink(), "#")
	if !found {
		t.Fatal("the founder printed no setup link")
	}
	key := passkeytest.New(t, console.origin)
	options := console.expect(http.StatusOK, http.MethodPost, "/admin/api/setup/begin",
		map[string]string{"token": token, "name": "lab"})
	answer, err := key.Create(options)
	if err != nil {
		t.Fatal(err)
	}
	console.expect(http.StatusNoContent, http.MethodPost, "/admin/api/setup/finish", answer)

	// The leaf's enrollment pends in the console until the operator
	// approves it.
	leaf := b.app.IA().String()
	var ask string
	Poll(t, "the leaf's enrollment ask", func() bool {
		_, asks := console.nodes()
		for _, a := range asks {
			if a.Claim == leaf && a.State == "pending" {
				ask = a.ID
				return true
			}
		}
		return false
	})
	if holdsChain(t.Context(), b) {
		t.Fatal("the leaf enrolled before the operator approved it")
	}
	console.expect(http.StatusNoContent, http.MethodPost, "/admin/api/asks/"+ask+"/approve", nil)
	Poll(t, "the approved leaf to enroll", func() bool { return holdsChain(t.Context(), b) })

	// A key naming the leaf mints once the console lists the leaf with its
	// host endpoint, and the response names both.
	var endpoint string
	Poll(t, "the leaf listed with its host endpoint", func() bool {
		nodes, _ := console.nodes()
		for _, n := range nodes {
			if n.IA == leaf && n.Endpoint != "" {
				endpoint = n.Endpoint
				return true
			}
		}
		return false
	})
	var minted struct {
		ID       string `json:"id"`
		Key      string `json:"key"`
		Node     string `json:"node"`
		Endpoint string `json:"endpoint"`
	}
	if err := json.Unmarshal(console.expect(http.StatusOK, http.MethodPost, "/admin/api/keys",
		map[string]any{"description": "lab", "days": 1, "node": leaf}), &minted); err != nil {
		t.Fatal(err)
	}
	if minted.Node != leaf || minted.Endpoint != endpoint {
		t.Fatalf("the minting answered %+v, want the leaf at %s", minted, endpoint)
	}

	// The host joins unattended onto the leaf, listed with the key's note,
	// the leaf's endpoint, and its open stream.
	ips := hostUp(t, tailnetHost(t, "keyed", place.controlURL, minted.Key))
	if len(ips) != 1 {
		t.Fatalf("the keyed host's addresses = %v", ips)
	}
	var listed portalHost
	Poll(t, "the host listed connected with the key's note", func() bool {
		for _, h := range console.hosts() {
			if h.Addr == ips[0].String() && h.Note == "portal auth key "+minted.ID && h.Connected {
				listed = h
				return true
			}
		}
		return false
	})
	if listed.Owner != leaf || listed.Endpoint != endpoint {
		t.Fatalf("the host is listed on %s at %s, want the leaf at %s", listed.Owner, listed.Endpoint, endpoint)
	}

	// The release closes the host's tunnel: the leaf drops the peer, and
	// the console lists it no more.
	Poll(t, "the leaf programming the host", func() bool { return programsHost(b, ips[0]) })
	console.expect(http.StatusNoContent, http.MethodDelete, "/admin/api/hosts/"+listed.NodeKey, nil)
	Poll(t, "the leaf dropping the released host", func() bool { return !programsHost(b, ips[0]) })
	for _, h := range console.hosts() {
		if h.NodeKey == listed.NodeKey {
			t.Errorf("the console still lists the released host: %+v", h)
		}
	}
}
