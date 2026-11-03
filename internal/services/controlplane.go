package services

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"
	"go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"

	"github.com/fancl20/cion/internal/supervise"
	"github.com/fancl20/cion/pkg/apps/voting"
	"github.com/fancl20/cion/pkg/core/controlplane"
	"github.com/fancl20/cion/pkg/core/liveness"
	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/core/webpki"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/modules/links"
	linkbbolt "github.com/fancl20/cion/pkg/modules/links/impl/bbolt"
	"github.com/fancl20/cion/pkg/modules/membership"
	"github.com/fancl20/cion/pkg/modules/pathdb"
	pathdbbbolt "github.com/fancl20/cion/pkg/modules/pathdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/modules/topology"
	trustbbolt "github.com/fancl20/cion/pkg/modules/trustdb/impl/bbolt"
)

// setupControlPlane brings up the node's control plane, in phases: the state
// databases and keys — the link store among them — the trust role (the
// role's parts, the products the later phases take, and the role's own
// loops), the messenger (trust engine and peer client), the BFD health
// monitor, beaconing (the lookup, beaconer, and path provider closing their
// cycle), the wiring of the loaded topology provider over what the phases
// built, the control endpoint's socket and the provider's mounted services,
// and the echo responder. Each phase registers what it acquires with the
// node's group as it goes, so a failed boot's Stop releases a partial node.
func (n *node) setupControlPlane(ctx context.Context) error {
	if err := n.openState(ctx); err != nil {
		return err
	}
	if err := n.setupTrustRole(ctx); err != nil {
		return err
	}
	n.setupMembership()
	if err := n.buildMessenger(); err != nil {
		return err
	}
	if err := n.assembleMonitor(); err != nil {
		return err
	}
	if err := n.buildBeaconing(); err != nil {
		return err
	}
	n.wireTopology()
	if err := n.assembleEndpoint(); err != nil {
		return err
	}
	return n.assembleResponder()
}

// storeLockTimeout bounds the wait on a database's file lock. A node holds
// its databases for its lifetime, so a lock still held at the bound is
// another process serving from the same state directory.
const storeLockTimeout = time.Second

// openState opens the trust, membership, path, and link databases and the AS
// key under the state directory. A node may start with zero links: the store is empty
// until a neighbor joins, the selection loop promotes one, or the loaded
// provider seeds it — the first-start neighbor requirement being the
// provider's to satisfy, by a --topology.neighbor or a non-empty link-set.
func (n *node) openState(ctx context.Context) error {
	trustDB, err := openStore(n.cfg.State, "trust.db", trustbbolt.New)
	if err != nil {
		return fmt.Errorf("opening trust DB: %w", err)
	}
	n.group.Own("trust database", trustDB.Close)
	n.trustDB = trustDB
	memberStore, err := openStore(n.cfg.State, "membership.db", membership.OpenStore)
	if err != nil {
		return fmt.Errorf("opening membership store: %w", err)
	}
	n.group.Own("membership store", memberStore.Close)
	n.memberStore = memberStore
	asKey, err := trust.LoadOrCreateASKey(n.cfg.State)
	if err != nil {
		return fmt.Errorf("loading AS key: %w", err)
	}
	n.asKey = asKey
	pathDB, err := openStore(n.cfg.State, "path.db", pathdbbbolt.New)
	if err != nil {
		return fmt.Errorf("opening path DB: %w", err)
	}
	n.group.Own("path database", pathDB.Close)
	n.pathDB = pathDB
	linkStore, err := openStore(n.cfg.State, "links.db", linkbbolt.New)
	if err != nil {
		return fmt.Errorf("opening link DB: %w", err)
	}
	n.group.Own("link database", linkStore.Close)
	// Every write to the store, whoever makes it, signals the generation
	// swap and the link state's next publish.
	n.linkStore = links.Notifying(linkStore, n.notifyLinkChange)
	return nil
}

// openStore opens the named database under the state directory, a lock
// still held at storeLockTimeout refused as the directory in use.
func openStore[DB any](state, name string, open func(string, *bbolt.Options) (DB, error)) (DB, error) {
	db, err := open(filepath.Join(state, name), &bbolt.Options{Timeout: storeLockTimeout})
	if errors.Is(err, bolterrors.ErrTimeout) {
		err = fmt.Errorf("the state directory %s is in use: another process holds %s",
			state, name)
	}
	return db, err
}

// roleLoop is one of the role's own loops: its name, its policy, and its
// run, which start hands to the group.
type roleLoop struct {
	name   string
	policy supervise.Policy
	run    func(context.Context) error
}

// setupTrustRole builds the node's trust role in one switch over the
// resolved role. Each case builds the role's parts, sets the products the
// later phases take, and adds the role's own loops. Both core tiers first
// promote the material a roll staged once the newest pinned TRC names it,
// so the material they load covers that TRC wherever the roll stopped.
func (n *node) setupTrustRole(ctx context.Context) error {
	switch n.cfg.role {
	case trust.ASTypeCore:
		return n.setupFounder(ctx)
	case trust.ASTypeAuthoritative:
		return n.setupAuthoritative(ctx)
	default:
		return n.setupNormal()
	}
}

// setupFounder builds the founding core's parts: its core keys, its TRC —
// genesis, or the newest pinned — the issuer anchored in it, the decision
// on submitted TRC updates the voting application hands each submission
// to, its first chain by self-enrollment — the chain lifecycle's first
// pass — and its WebPKI identity, prepared whatever the applications: the
// node's HTTPS server, assembled after they mount, serves it and answers
// the ACME TLS-ALPN challenge on it, so no TLS path branches on an
// application's presence.
// Its loops renew by self-issue, roll by local cast, manage an ACME-managed
// certificate, and run the selected authorizer's own loops when the method
// has them.
func (n *node) setupFounder(ctx context.Context) error {
	newest, err := n.promoteStaged(ctx)
	if err != nil {
		return err
	}
	keys, err := trust.LoadOrCreateCoreKeys(n.cfg.State)
	if err != nil {
		return err
	}
	trc, err := trust.Genesis(ctx, n.trustDB, n.ident.ia, keys)
	if err != nil {
		return fmt.Errorf("TRC genesis: %w", err)
	}
	// The issuer anchors in the newest pinned TRC, not the base: a restart
	// after a rotation finds the successor whose root certificate the live
	// keys hold, and the chains issue under it from the boot on.
	if !newest.IsZero() {
		trc = newest
	}
	issuer, err := trust.NewIssuer(n.ident.ia, keys.IssuerKeys, trc)
	if err != nil {
		return fmt.Errorf("creating issuer: %w", err)
	}
	issuer.ChainValidity = n.cfg.Pacing.ChainValidity
	decider := &trust.TRCDecider{
		DB:         n.trustDB,
		IA:         n.ident.ia,
		Sensitive:  keys.Sensitive,
		Authorizer: n.cfg.enrollAuth,
	}
	if err := trust.SelfIssue(ctx, n.trustDB, issuer, n.ident.ia, n.asKey); err != nil {
		return fmt.Errorf("self-enrolling core: %w", err)
	}
	manager, err := webpki.PrepareTLSCert(webpki.TLSCertConfig{
		Domain:   n.cfg.Domain,
		Email:    n.cfg.AcmeEmail,
		CertFile: n.cfg.CertFile,
		KeyFile:  n.cfg.KeyFile,
		Storage:  filepath.Join(n.cfg.State, "certs"),
	})
	if err != nil {
		return err
	}
	n.group.Own("certificate manager", manager.Close)
	n.issuer = issuer
	n.trcDecision = decider
	n.removeNode = n.nodeRemoval(decider)
	n.certMgr = manager
	n.webPKI = manager.TLSConfig()
	n.roleLoops = []roleLoop{
		{"enrollment", supervise.Fatal, func(ctx context.Context) error {
			return trust.RunEnrollment(ctx,
				n.enrollment(trust.FounderRenewal(issuer)))
		}},
		// The founder's rotation watch: its own three certificates roll
		// inside the cast it signs itself, serialized on the decision the
		// submissions take too.
		{"rotation watch", supervise.Fatal, func(ctx context.Context) error {
			trust.RunRotation(ctx,
				n.rotation(trust.FounderRoll(decider, issuer)))
			return nil
		}},
	}
	if manager.ACMEManaged() {
		// The certificate maintenance retries a failed issuance while the
		// node serves on; static files manage nothing and start no loop.
		n.roleLoops = append(n.roleLoops,
			roleLoop{"certificate management", supervise.Degrade, manager.Manage})
	}
	if run := n.cfg.enrollRun; run != nil {
		// The selected authorizer's own loops — the Telegram poll.
		n.roleLoops = append(n.roleLoops, roleLoop{"enrollment authorizer", supervise.Degrade,
			func(ctx context.Context) error {
				run(ctx)
				return nil
			}})
	}
	return nil
}

// setupAuthoritative builds the authoritative core's parts: its voting
// material — the regular voting key, and the self-signed certificate over it
// naming the completed ISD-AS — its issuing material — the root and CA keys,
// and the self-signed root certificate the same way — the issuer, anchored
// in the newest pinned TRC once that carries the root, and the core client.
// Its loops renew — remotely until the issuer is anchored, by self-issue
// from then on — and cast the onboarding update, and roll by submission,
// both submitting to the founder's voting application over the verified
// peer channel, the submission identified by the node's chain.
func (n *node) setupAuthoritative(ctx context.Context) error {
	newest, err := n.promoteStaged(ctx)
	if err != nil {
		return err
	}
	votingKey, err := trust.LoadOrCreateVotingKey(n.cfg.State)
	if err != nil {
		return fmt.Errorf("loading voting key: %w", err)
	}
	votingCert, err := trust.LoadOrCreateVotingCert(n.cfg.State, n.ident.ia, votingKey)
	if err != nil {
		return fmt.Errorf("loading voting certificate: %w", err)
	}
	issuerKeys, err := trust.LoadOrCreateIssuerKeys(n.cfg.State)
	if err != nil {
		return fmt.Errorf("loading issuer keys: %w", err)
	}
	rootCert, err := trust.LoadOrCreateRootCert(n.cfg.State, n.ident.ia, issuerKeys.Root)
	if err != nil {
		return fmt.Errorf("loading root certificate: %w", err)
	}
	issuer, err := trust.NewIssuer(n.ident.ia, issuerKeys, newest)
	if err != nil {
		return fmt.Errorf("creating issuer: %w", err)
	}
	issuer.ChainValidity = n.cfg.Pacing.ChainValidity
	coreClt, err := n.coreClient()
	if err != nil {
		return err
	}
	n.issuer = issuer
	n.remote = coreClt
	voting := trust.KeyCert{Key: votingKey, Cert: votingCert}
	root := trust.KeyCert{Key: issuerKeys.Root, Cert: rootCert}
	n.roleLoops = []roleLoop{
		// The onboarding's failure is terminal: the loop returns it, and the
		// node stops with it as the cause.
		{"enrollment", supervise.Fatal, func(ctx context.Context) error {
			return trust.RunEnrollment(ctx, n.enrollment(trust.AuthoritativeRenewal(
				coreClt, n.issuers(), n.submitter(), voting, root, issuer)))
		}},
		// The authoritative core's rotation watch: its certificates roll
		// through the same channel its join used, by a regular update its
		// current keys sign.
		{"rotation watch", supervise.Fatal, func(ctx context.Context) error {
			trust.RunRotation(ctx,
				n.rotation(trust.AuthoritativeRoll(coreClt, n.submitter(), issuer)))
			return nil
		}},
	}
	return nil
}

// setupNormal builds the normal node's one part, the core client. Its loop
// renews at the issuers, and enrolls through the core client.
func (n *node) setupNormal() error {
	coreClt, err := n.coreClient()
	if err != nil {
		return err
	}
	n.remote = coreClt
	n.roleLoops = []roleLoop{
		{"enrollment", supervise.Fatal, func(ctx context.Context) error {
			return trust.RunEnrollment(ctx,
				n.enrollment(trust.NormalRenewal(coreClt, n.issuers())))
		}},
	}
	return nil
}

// coreClient builds the client every role but the founder enrolls with the
// founder through, over the WebPKI-verified channel, the founder's control
// service resolved through the drafts' exchange when the dial wants an
// underlay address.
func (n *node) coreClient() (*webpki.CoreClient, error) {
	// The client socket takes an ephemeral port on the control address;
	// the local router delivers the core's replies to it. The resolution
	// exchange takes its own beside it: the exchange reads its conn for
	// each reply's wait, and a conn the client's QUIC transport reads
	// would share its packets with that loop.
	conn, err := n.controlConn(0)
	if err != nil {
		return nil, err
	}
	n.group.Own("core client conn", conn.Close)
	resolutionConn, err := n.controlConn(0)
	if err != nil {
		return nil, err
	}
	n.group.Own("resolution conn", resolutionConn.Close)
	coreClt, err := webpki.NewCoreClient(webpki.CoreClientConfig{
		Domain:  n.cfg.Domain,
		Conn:    conn,
		RootCAs: n.cfg.RootCAs,
		Locator: n.founderRoute,
		ResolveService: func(ctx context.Context, peer *scion.Addr) (netip.AddrPort, error) {
			return scionrpc.ResolveService(ctx, resolutionConn, peer)
		},
	})
	if err != nil {
		return nil, err
	}
	// The client's Close closes its QUIC transport alone; registered after
	// its conns, it releases first.
	n.group.Own("core client", coreClt.Close)
	n.coreClt = coreClt
	return coreClt, nil
}

// submitter returns a submitter to the founder's voting application over
// the node's verified peer channel. The channel is the messenger phase's,
// built after the role's, so the loops build their submitter as they start.
func (n *node) submitter() *voting.Submitter {
	return voting.NewSubmitter(n.peerClt.VerifiedClient(), n.founderRoute)
}

// issuers returns the remote that renews the node's chain at the issuers
// over the node's verified peer channel, built as the loops start as the
// submitter is.
func (n *node) issuers() trust.Remote {
	return n.peerClt.Issuers(n.issuerRoutes)
}

// enrollment configures the node's chain lifecycle with the role's renewal.
func (n *node) enrollment(renewal trust.Renewal) trust.EnrollmentConfig {
	return trust.EnrollmentConfig{
		IA:               n.ident.ia,
		DB:               n.trustDB,
		Key:              n.asKey,
		Renewal:          renewal,
		RetryInterval:    n.cfg.Pacing.Enrollment,
		InspectInterval:  n.cfg.Pacing.EnrollmentInspect,
		RenewalThreshold: n.cfg.Pacing.RenewalThreshold,
	}
}

// rotation configures a core's rotation watch with the holder's roll.
func (n *node) rotation(roll trust.Roll) trust.RotationConfig {
	return trust.RotationConfig{
		IA:              n.ident.ia,
		DB:              n.trustDB,
		State:           n.cfg.State,
		Roll:            roll,
		Threshold:       n.cfg.Pacing.RotationThreshold,
		RetryInterval:   n.cfg.Pacing.Enrollment,
		InspectInterval: n.cfg.Pacing.Enrollment,
	}
}

// promoteStaged promotes the material a roll staged once the newest pinned
// TRC names it, and returns that TRC, zero on a first start.
func (n *node) promoteStaged(ctx context.Context) (cppki.SignedTRC, error) {
	newest, err := n.trustDB.SignedTRC(ctx, trust.NewestTRCID(n.ident.ia.ISD()))
	if err != nil {
		return cppki.SignedTRC{}, fmt.Errorf("reading the newest pinned TRC: %w", err)
	}
	if _, err := trust.PromoteStaged(n.cfg.State, n.ident.ia, newest.TRC); err != nil {
		return cppki.SignedTRC{}, fmt.Errorf("promoting the staged voting material: %w", err)
	}
	return newest, nil
}

// buildMessenger builds the trust engine and the peer client every node
// beacons and fetches segments through.
func (n *node) buildMessenger() error {
	// The provider behind the engine is DB-first: a received beacon's
	// missing material comes from its sender through the peer client; the
	// rest, and what a sender cannot serve, comes from the founder's
	// endpoint through the core client over the SCION-native transport, on
	// every role but the founder itself.
	provider := &trust.NetworkProvider{DB: n.trustDB, Remote: n.remote}
	n.engine = trust.NewEngine(n.ident.ia, n.asKey, provider, n.members)

	peerConn, err := n.controlConn(0)
	if err != nil {
		return err
	}
	// The client's Close closes its QUIC transport alone; registered after
	// the conn, it releases first.
	n.group.Own("peer conn", peerConn.Close)
	peerClt := controlplane.NewPeerClient(scionrpc.PeerClientConfig{
		Credentials: n.engine,
		Key:         n.engine.Key,
		Conn:        peerConn,
		PathTo: func(dst addr.IA) *spath.Decoded {
			path, err := n.pathProvider.LocalPath(dst)
			if err != nil {
				return nil
			}
			return path
		},
	})
	n.group.Own("peer client", peerClt.Close)
	n.peerClt = peerClt
	// The client's credentials come from the engine, so the provider learns
	// the senders' fetcher once the client exists, before any beacon
	// arrives.
	provider.Peer = peerClt.Fetcher
	return nil
}

// buildBeaconing builds the segment lookup, the beaconer, and the path
// provider that closes the cycle between them: the provider resolves
// through the lookup, the lookup fetches through the peer client, and the
// beaconer bootstraps the provider. The beaconer reads the link table live —
// a node may start with zero links — and the store's snapshot alone is its
// neighbor identity.
func (n *node) buildBeaconing() error {
	cores := func(isd addr.ISD) []addr.IA {
		ias, err := n.engine.CoreASes(isd)
		if err != nil {
			slog.Warn("Enumerating core ASes from the pinned TRC", "err", err)
			return nil
		}
		return ias
	}

	// Both core selections take the tier: the founding and the authoritative
	// core alike originate beacons, terminate core beacons, and serve the
	// core's segment-lookup handler.
	coreTier := n.cfg.role != trust.ASTypeNormal
	n.lookup = controlplane.NewLookupService(controlplane.LookupConfig{
		IA:     n.ident.ia,
		DB:     n.pathDB,
		IsCore: coreTier,
		Cores:  cores,
		Fetch:  n.peerClt.Segments,
	})

	beacons := controlplane.NewBeaconStore()
	n.beaconStore = beacons
	beaconer, err := controlplane.NewBeaconer(controlplane.BeaconerConfig{
		IA:                   n.ident.ia,
		Engine:               n.engine,
		MACKey:               n.ident.key,
		Store:                beacons,
		DB:                   n.pathDB,
		Links:                n.bus.Links(),
		Latencies:            n.bus.Latencies(),
		Sender:               n.peerClt,
		Core:                 coreTier,
		PropagationInterval:  n.cfg.Pacing.Propagation,
		RegistrationInterval: n.cfg.Pacing.Registration,
	})
	if err != nil {
		return err
	}
	n.beaconer = beaconer

	n.pathProvider = &scion.PathProvider{
		IA:            n.ident.ia,
		DB:            n.pathDB,
		Lookup:        n.lookup.Down,
		Bootstrap:     beaconer.BootstrapRoute,
		Cores:         cores,
		InterfaceDown: n.bus.InterfaceDown(),
		Links:         n.bus.Links(),
		Measurements:  n.bus.PathMeasurements(),
		Requests:      n.bus.PathRequests(),
	}
	return nil
}

// wireTopology delivers the phases' products to the loaded provider: the
// completed identity, the store its decisions land in, the peer client its
// in-band requests ride, the path provider its comparator baselines with, the
// trust engine its directory channel authenticates with, and the node's bus,
// whose link state carries the monitor's verdicts and the data plane's
// per-link observations the confirm's agreement rule reads, and whose latency
// topic the selection's samples land on. The last step before the provider
// mounts and runs, and the one direction the dependency ever crosses: the
// application imports the core and the shared libraries, never the reverse.
func (n *node) wireTopology() {
	n.topology.Wire(topology.Environment{
		IA:     n.ident.ia,
		Store:  n.linkStore,
		Peer:   n.peerClt,
		Paths:  n.pathProvider,
		Engine: n.engine,
		Bus:    n.bus,
	})
}

// assembleMonitor builds the health monitor over the link store: a BFD
// session per serving link whatever the loaded provider is doing — a
// neighbor's detection of the node depends on the node answering its BFD,
// which makes answering a service of the node itself. It is assembled
// before the first data plane generation, so every generation finds a
// session per serving link, and the file provider's nodes get them too:
// the monitor reads the store, not the provider. Each change of its
// verdicts nudges the link state.
func (n *node) assembleMonitor() error {
	monitor, err := liveness.NewHealthMonitor(liveness.HealthMonitorConfig{
		IA:       n.ident.ia,
		MACKey:   n.ident.key,
		Store:    n.linkStore,
		Interval: n.cfg.Pacing.BFD,
		OnChange: n.nudgeLinkState,
	})
	if err != nil {
		return err
	}
	n.monitor = monitor
	return nil
}

// assembleEndpoint binds the control endpoint's socket. Every node serves
// its ConnectRPC services over HTTP/3 on the endpoint port — the drafts'
// beside the loaded provider's mounts, the drafts' service resolution
// answering beside them on the same socket — and the founder's endpoint
// additionally serves the bootstrap channel, under the WebPKI identity its
// role prepared, for clients offering its domain as the TLS server name.
func (n *node) assembleEndpoint() error {
	endpointConn, err := n.controlConn(scionrpc.EndpointPort)
	if err != nil {
		return err
	}
	n.group.Own("endpoint conn", endpointConn.Close)
	n.endpointConn = endpointConn

	// The provider releases what Mounts binds, a Mounts that failed partway
	// included.
	n.group.Own("topology provider", n.topology.Close)
	mounts, err := n.topology.Mounts()
	if err != nil {
		return err
	}
	// The exporter's registry beside the provider's mounts, the same
	// middleware around it: nothing new binds, for the endpoint's socket is
	// the listener.
	metrics, err := metricsMount()
	if err != nil {
		return err
	}
	mounts = append(mounts, metrics)
	n.services = &controlplane.Services{
		TrustService: &controlplane.TrustService{
			DB:          n.trustDB,
			Issuer:      n.issuer,
			Enrolls:     n.cfg.role == trust.ASTypeCore,
			Authorizer:  n.cfg.enrollAuth,
			Membership:  n.members,
			MinInterval: n.cfg.Pacing.RendezvousRate,
		},
		SegmentService: &controlplane.SegmentService{
			Beaconer: n.beaconer,
			Lookup:   n.lookup,
		},
		Mounts: mounts,
	}
	return nil
}

// scionConn returns a SCION connection bound to the control address's host
// with the given port, sending through the node's internal link. Every conn
// resolves its one-hop writes over the links the node can send over and
// publishes on the node's interface-down topic — each receive path recognizes
// the signal the data plane's egress-down branch sends back — and, under the
// wildcard bind, which names no host itself, names the wildcard host as its
// packets' source and its service-resolution answers' host: an address the
// node's own router delivers to.
func (n *node) scionConn(port uint16) (*scion.Conn, error) {
	return scion.NewConn(n.connConfig(port))
}

// controlConn returns a SCION connection as scionConn does whose packets carry
// the control DSCP, which the node's data plane serves before data: the conns
// of the control plane, the bootstrap client, the echo responder, and the
// topology source.
func (n *node) controlConn(port uint16) (*scion.Conn, error) {
	cfg := n.connConfig(port)
	cfg.Control = true
	return scion.NewConn(cfg)
}

// connConfig returns the configuration of the node's SCION conns, bound to the
// control address's host with the given port.
func (n *node) connConfig(port uint16) scion.ConnConfig {
	return scion.ConnConfig{
		IA:            n.ident.ia,
		Bind:          netip.AddrPortFrom(n.cfg.controlAddr.Addr(), port).String(),
		InternalAddr:  n.cfg.internalAddr.String(),
		MACKey:        n.ident.key,
		Links:         n.bus.Links(),
		InterfaceDown: n.bus.InterfaceDown(),
		WildcardHost:  n.wildcardHost.resolve,
		Sockets:       n.sockets,
	}
}

// founderRoute returns the route to the founding core — the core this node
// enrolls with, the one whose voting application decides its submissions
// and whose directories serve it — the drafts' own way of reaching a core:
// the one-hop path when the founder is a direct neighbor with its verdict
// up, addressed to its control service; else the reversed freshest up
// segment from the founder — or, before any is verified, the bootstrap
// beacon's route — addressed to the control service the same way. The
// founder is the core the newest pinned TRC's sensitive voting certificate
// names; before any TRC is pinned, the bootstrap route takes turns among
// the beacons' origins. The endpoint address is resolved, not remembered:
// the drafts' service resolution answers it at dial time. Local state only:
// resolving a route inside a dial must not spawn RPCs over the transport
// being dialed.
func (n *node) founderRoute() *scion.Addr {
	founder, err := n.engine.FounderAS(n.ident.ia.ISD())
	if err != nil {
		slog.Error("Reading the founding core", "err", err)
		return nil
	}
	if !founder.IsZero() {
		// The one-hop shortcut: a usable link reaches the founder directly
		// — a link the monitor marked down falls through to the composed
		// route.
		for ifID, neighborIA := range n.bus.Links().Latest().Usable() {
			if neighborIA.Equal(founder) {
				return &scion.Addr{IA: founder, Service: addr.SvcCS, IfID: ifID}
			}
		}
	}
	// At distance: the founder's freshest up segment, or the bootstrap
	// beacon's before any is verified, reversed.
	freshest := func() addr.IA {
		if founder.IsZero() {
			return 0
		}
		cores := n.freshestUpCores(map[addr.IA]bool{founder: true})
		if len(cores) == 0 {
			return 0
		}
		return cores[0]
	}
	for _, core := range []func() addr.IA{freshest, n.beaconer.BootstrapCore} {
		if coreIA := core(); !coreIA.IsZero() {
			if path, err := n.pathProvider.LocalPath(coreIA); err == nil {
				return &scion.Addr{IA: coreIA, Service: addr.SvcCS, Path: path}
			}
		}
	}
	return nil
}

// issuerRoutes returns the routes to the issuers — the cores whose root
// certificate the newest pinned TRC carries — in the order a renewal asks
// them. Local state only, as the founder route.
func (n *node) issuerRoutes() []*scion.Addr {
	issuers := n.issuerASes()
	return orderIssuerRoutes(issuers, n.bus.Links().Latest().Usable(),
		n.freshestUpCores(issuers), n.pathProvider.LocalPath)
}

// orderIssuerRoutes orders the routes to the issuers: those a usable link
// reaches, by ISD-AS, over the one-hop path, then the others in the order
// freshest lists them — the freshest up segment's origin first — over the
// path localPath composes to each.
func orderIssuerRoutes(
	issuers map[addr.IA]bool,
	usable map[uint16]addr.IA,
	freshest []addr.IA,
	localPath func(addr.IA) (*spath.Decoded, error),
) []*scion.Addr {

	var routes []*scion.Addr
	linked := make(map[addr.IA]bool)
	for ifID, neighborIA := range usable {
		if issuers[neighborIA] && !linked[neighborIA] {
			linked[neighborIA] = true
			routes = append(routes, &scion.Addr{IA: neighborIA, Service: addr.SvcCS, IfID: ifID})
		}
	}
	slices.SortFunc(routes, func(a, b *scion.Addr) int { return cmp.Compare(a.IA, b.IA) })
	for _, core := range freshest {
		if linked[core] {
			continue
		}
		if path, err := localPath(core); err == nil {
			routes = append(routes, &scion.Addr{IA: core, Service: addr.SvcCS, Path: path})
		}
	}
	return routes
}

// issuerASes returns the cores whose root certificate the newest pinned TRC
// carries — the ASes a root certificate names as its subject, exactly the
// nodes that can serve a chain renewal — as a set.
func (n *node) issuerASes() map[addr.IA]bool {
	ias, err := n.engine.IssuerASes(n.ident.ia.ISD())
	if err != nil {
		slog.Error("Enumerating the issuer cores", "err", err)
		return nil
	}
	set := make(map[addr.IA]bool, len(ias))
	for _, ia := range ias {
		set[ia] = true
	}
	return set
}

// freshestUpCores returns the cores among the given ones that originated an
// up segment the node has verified, the one whose freshest segment is
// freshest first: the cores its own termination stands behind. Empty when
// none is stored.
func (n *node) freshestUpCores(cores map[addr.IA]bool) []addr.IA {
	segs, err := n.pathDB.Get(context.Background(), pathdb.Query{Type: pathdb.SegmentTypeUp})
	if err != nil {
		slog.Error("Reading the path database", "err", err)
		return nil
	}
	freshest := make(map[addr.IA]time.Time)
	for _, seg := range segs {
		origin := seg.FirstIA()
		if !cores[origin] {
			continue
		}
		if ts := seg.PCB.Timestamp(); ts.After(freshest[origin]) {
			freshest[origin] = ts
		}
	}
	ordered := slices.Collect(maps.Keys(freshest))
	slices.SortFunc(ordered, func(a, b addr.IA) int {
		return freshest[b].Compare(freshest[a])
	})
	return ordered
}
