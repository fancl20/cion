package bus

import "github.com/scionproto/scion/pkg/addr"

// TagGroup is the node tag that names the group a node belongs to, whose
// members share the routes into it. The topology provider applies it.
const TagGroup = "group"

// NodeTags is the tags of the nodes the node knows, itself among them: each
// key's value on each node. A node carries at most one value per key, and an
// empty value is no tag. A published NodeTags is never mutated. The zero
// NodeTags tags nothing.
type NodeTags struct {
	values map[string]map[addr.IA]string
}

// Tag returns the node's value of the key, empty for none.
func (t NodeTags) Tag(ia addr.IA, key string) string {
	return t.values[key][ia]
}

// With returns the tags with the key's values replaced by the given ones,
// copied, their empty values left out.
func (t NodeTags) With(key string, values map[addr.IA]string) NodeTags {
	next := NodeTags{values: make(map[string]map[addr.IA]string, len(t.values)+1)}
	for k, v := range t.values {
		if k != key {
			next.values[k] = v
		}
	}
	own := make(map[addr.IA]string, len(values))
	for ia, v := range values {
		if v != "" {
			own[ia] = v
		}
	}
	if len(own) > 0 {
		next.values[key] = own
	}
	return next
}
