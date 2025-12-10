package controlplane

import "sync"

// Neighbor represents a directly connected SCION node.
type Neighbor struct {
	ISD_AS  SCIONAddress
	Address string // IP:Port overlay address
}

// Discovery manages neighbor discovery.
type Discovery struct {
	mu        sync.RWMutex
	neighbors map[SCIONAddress]Neighbor
}

// NewDiscovery creates a new Discovery module.
func NewDiscovery() *Discovery {
	return &Discovery{
		neighbors: make(map[SCIONAddress]Neighbor),
	}
}

// AddNeighbor registers a direct neighbor.
func (d *Discovery) AddNeighbor(isdAs SCIONAddress, addr string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.neighbors[isdAs] = Neighbor{
		ISD_AS:  isdAs,
		Address: addr,
	}
}

// GetNeighbors returns a list of all known neighbors.
func (d *Discovery) GetNeighbors() []Neighbor {
	d.mu.RLock()
	defer d.mu.RUnlock()
	neighbors := make([]Neighbor, 0, len(d.neighbors))
	for _, n := range d.neighbors {
		neighbors = append(neighbors, n)
	}
	return neighbors
}

// GetNeighbor returns a specific neighbor if it exists.
func (d *Discovery) GetNeighbor(isdAs SCIONAddress) (Neighbor, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	n, ok := d.neighbors[isdAs]
	return n, ok
}
