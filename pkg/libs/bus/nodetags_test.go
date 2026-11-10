package bus

import (
	"testing"

	"github.com/scionproto/scion/pkg/addr"
)

// TestNodeTags checks the tags: a key's values replace the key's last ones
// whole, copied, their empty values left out, and leave every other key's
// values as they were; a node or a key the tags lack reads empty, as every
// node of the zero tags does.
func TestNodeTags(t *testing.T) {
	const other = "other"
	a, b := addr.MustIAFrom(20, 1), addr.MustIAFrom(20, 2)
	groups := map[addr.IA]string{a: "g1", b: ""}
	tags := NodeTags{}.With(TagGroup, groups).With(other, map[addr.IA]string{a: "v"})
	groups[a] = "g2"
	if got := tags.Tag(a, TagGroup); got != "g1" {
		t.Errorf("a's group = %q, want g1, unchanged by its map's later write", got)
	}
	if _, ok := tags.values[TagGroup][b]; ok {
		t.Error("an empty value was kept")
	}
	if got := tags.Tag(a, other); got != "v" {
		t.Errorf("a's other tag = %q, want v", got)
	}

	next := tags.With(TagGroup, map[addr.IA]string{b: "g3"})
	if got := next.Tag(a, TagGroup); got != "" {
		t.Errorf("a's group past the replacement = %q, want none", got)
	}
	if got := next.Tag(b, TagGroup); got != "g3" {
		t.Errorf("b's group = %q, want g3", got)
	}
	if got := next.Tag(a, other); got != "v" {
		t.Errorf("a's other tag past the group's replacement = %q, want v", got)
	}
	if got := tags.Tag(b, TagGroup); got != "" {
		t.Errorf("the replacement changed the tags it replaced: b's group = %q", got)
	}
	if _, ok := next.With(TagGroup, nil).values[TagGroup]; ok {
		t.Error("a key replaced by no value was kept")
	}
	var zero NodeTags
	if got := zero.Tag(a, TagGroup); got != "" {
		t.Errorf("the zero tags' group = %q, want none", got)
	}
}
