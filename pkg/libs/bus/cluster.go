package bus

import "github.com/scionproto/scion/pkg/addr"

// Cluster is the cluster the node joined: its members, the node among them,
// as one selection window computed them. A published Cluster is never
// mutated. The zero Cluster holds no member: the node joined none.
type Cluster struct {
	members map[addr.IA]bool
}

// NewCluster returns the cluster of the given members.
func NewCluster(members ...addr.IA) Cluster {
	c := Cluster{members: make(map[addr.IA]bool, len(members))}
	for _, ia := range members {
		c.members[ia] = true
	}
	return c
}

// Has reports whether the node is one of the cluster's members.
func (c Cluster) Has(ia addr.IA) bool {
	return c.members[ia]
}
