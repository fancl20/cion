package pki

import (
	"encoding/asn1"
	"time"
)

// asn1ID is used to encode and decode the TRC ID, duplicated from cppki/trc_asn1.go for internal encoding.
type asn1ID struct {
	ISD    int64 `asn1:"iSD"`
	Serial int64 `asn1:"serialNumber"`
	Base   int64 `asn1:"baseNumber"`
}

// asn1Validity is used to encode and decode validity, duplicated from cppki/trc_asn1.go.
type asn1Validity struct {
	NotBefore time.Time `asn1:"notBefore,generalized"`
	NotAfter  time.Time `asn1:"notAfter,generalized"`
}

// asn1TRCPayload is used to encode and decode the TRC payload, duplicated from cppki/trc_asn1.go.
type asn1TRCPayload struct {
	Version           int64           `asn1:"version"`
	ID                asn1ID          `asn1:"iD"`
	Validity          asn1Validity    `asn1:"validity"`
	GracePeriod       int64           `asn1:"gracePeriod"`
	NoTrustReset      bool            `asn1:"noTrustReset"`
	Votes             []int64         `asn1:"votes"`
	Quorum            int64           `asn1:"votingQuorum"`
	CoreASes          []string        `asn1:"coreASes"`
	AuthoritativeASes []string        `asn1:"authoritativeASes"`
	Description       string          `asn1:"description,utf8"`
	Certificates      []asn1.RawValue `asn1:"certificates"`
}
