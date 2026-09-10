package dataplane

import (
	"math/rand/v2"
	"slices"
	"sync"

	"github.com/scionproto/scion/pkg/addr"
)

// Services is a generic anycast address map, for use by underlay providers to
// implement the SCION service mapping.
type Services[addrT comparable] struct {
	mtx sync.Mutex
	m   map[addr.SVC][]addrT
}

func NewServices[addrT comparable]() *Services[addrT] {
	return &Services[addrT]{m: make(map[addr.SVC][]addrT)}
}

func (s *Services[addrT]) AddSvc(svc addr.SVC, a addrT) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	addrs := s.m[svc]
	if slices.Contains(addrs, a) {
		return
	}
	s.m[svc] = append(addrs, a)
}

func (s *Services[addrT]) DelSvc(svc addr.SVC, a addrT) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	addrs := s.m[svc]
	index := slices.Index(addrs, a)
	if index == -1 {
		return
	}
	addrs[index] = addrs[len(addrs)-1]
	var zeroAddr addrT
	addrs[len(addrs)-1] = zeroAddr
	s.m[svc] = addrs[:len(addrs)-1]
}

func (s *Services[addrT]) Any(svc addr.SVC) (addrT, bool) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	addrs := s.m[svc]
	if len(addrs) == 0 {
		var zeroAddr addrT
		return zeroAddr, false
	}
	return addrs[rand.IntN(len(addrs))], true
}
