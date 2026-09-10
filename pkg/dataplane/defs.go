package dataplane

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Type int

const (
	Invalid Type = iota
	UDPIPv4
	UDPIPv6
	UDPIPv46
)

const (
	UDPIPv4Name  = "UDP/IPv4"
	UDPIPv6Name  = "UDP/IPv6"
	UDPIPv46Name = "UDP/IPv4+6"
)

const (
	// EndhostPort is the underlay port that SCION binds to on non-routers. Subject to
	// change during standardisation.
	EndhostPort = 30041
)

func (ot Type) String() string {
	switch ot {
	case UDPIPv4:
		return UDPIPv4Name
	case UDPIPv6:
		return UDPIPv6Name
	case UDPIPv46:
		return UDPIPv46Name
	default:
		return fmt.Sprintf("UNKNOWN (%d)", ot)
	}
}

func TypeFromString(s string) (Type, error) {
	switch strings.ToLower(s) {
	case strings.ToLower(UDPIPv4Name):
		return UDPIPv4, nil
	case strings.ToLower(UDPIPv6Name):
		return UDPIPv6, nil
	case strings.ToLower(UDPIPv46Name):
		return UDPIPv46, nil
	default:
		return Invalid, fmt.Errorf("Unknown underlay type: type: %s", s)
	}
}

func (ot *Type) UnmarshalJSON(data []byte) error {
	var strVal string
	if err := json.Unmarshal(data, &strVal); err != nil {
		return err
	}
	t, err := TypeFromString(strVal)
	if err != nil {
		return err
	}
	*ot = t
	return nil
}

func (ot Type) MarshalJSON() ([]byte, error) {
	return json.Marshal(ot.String())
}

func (ot Type) IsUDP() bool {
	switch ot {
	case UDPIPv4, UDPIPv6, UDPIPv46:
		return true
	}
	return false
}
