package trust

import (
	"fmt"

	"github.com/scionproto/scion/pkg/addr"
)

// ASType is the tiered role of an AS, coupling the spec's core, voting, and
// authoritative properties. The type decides which key material a node
// generates on first start.
type ASType int

const (
	// ASTypeNormal is a non-core AS. It holds no voting or CA key material;
	// it enrolls at the founding core and renews its chain at any core.
	ASTypeNormal ASType = iota
	// ASTypeAuthoritative is a core AS that joined its ISD over the network:
	// it holds a regular voting certificate and the issuing material — a
	// root certificate and a CA key — beside the AS key, and enrolls like
	// any node. Once its root is in the TRC it issues its own chain and
	// renews any node's; the founding core stays the ISD's sensitive voter
	// and its only issuer of first chains.
	ASTypeAuthoritative
	// ASTypeCore is the founding core of an ISD. It self-issues the base
	// TRC and signs certificate chains for the ISD, every first chain among
	// them.
	ASTypeCore
)

func (t ASType) String() string {
	switch t {
	case ASTypeNormal:
		return "normal"
	case ASTypeAuthoritative:
		return "authoritative"
	case ASTypeCore:
		return "core"
	default:
		return fmt.Sprintf("unknown (%d)", int(t))
	}
}

// ParseASType parses the configuration representation of the AS type.
func ParseASType(s string) (ASType, error) {
	switch s {
	case "normal":
		return ASTypeNormal, nil
	case "authoritative":
		return ASTypeAuthoritative, nil
	case "core":
		return ASTypeCore, nil
	default:
		return ASTypeNormal, fmt.Errorf("invalid AS type %q (want core, authoritative, or normal)", s)
	}
}

// minPrivateISD and maxPrivateISD delimit the ISD range recommended for
// private installations (control plane draft, Section 1.5.1).
const (
	minPrivateISD = 16
	maxPrivateISD = 63
)

// validateISD checks that the ISD of the given IA is in the private range.
func validateISD(ia addr.IA) error {
	if isd := ia.ISD(); isd < minPrivateISD || isd > maxPrivateISD {
		return fmt.Errorf("ISD %d out of private range [%d, %d]", isd,
			minPrivateISD, maxPrivateISD)
	}
	return nil
}
