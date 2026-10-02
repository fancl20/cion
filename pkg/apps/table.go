package apps

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
)

// Entry is one resident application's place in the table: the name the
// list selects by, the registration of the application's own run
// arguments, its role bounds, the applications it requires beside it, and
// the constructor that adapts the environment into the application's own
// configuration.
type Entry struct {
	// Name is the application's name, what --applications lists.
	Name string
	// RegisterFlags registers the entry's own run arguments over the
	// commands' flag sets, the destinations in the entry's block of
	// Arguments. Nil when the application takes no argument.
	RegisterFlags func(*pflag.FlagSet, *Arguments)
	// CoreOnly bounds the entry to the core role.
	CoreOnly bool
	// Requires names the applications the entry needs beside it: a list
	// that names this entry without one of them refuses the boot, for
	// requirements never imply.
	Requires []string
	// MissingArg names the entry's loading argument and why it refuses the
	// loading, when the entry's own arguments are refused — the inference
	// regime skips the entry and a list that names it refuses the boot,
	// the same fact read twice. "" when the entry loads on any arguments.
	MissingArg func(*Arguments) string
	// New constructs the application from the environment and the loaded —
	// the applications earlier in table order, where a borrower finds the
	// owner's exported surface.
	New func(*Environment, []Loaded) (Application, error)
}

// Table is the closed list of the resident applications in the order the
// borrows need: the WireGuard application first, its borrowers after,
// which is the reverse of the release. Adding an application adds a
// package beneath the roof and an entry here; the assembly walks the
// table and touches nothing.
var Table = []Entry{
	wireguardEntry,
	coordinationEntry,
	socksEntry,
	votingEntry,
}

// Loaded is one constructed application: its name beside what its entry's
// constructor returned. The list grows in table order as the constructors
// return, and the assembly's walks — the HTTPS mount, the starts, the
// reverse release — read it.
type Loaded struct {
	Name string
	App  Application
}

// AppOf returns the application the name names among the loaded, nil when
// the name did not load: the borrows' resolution point.
func AppOf(loaded []Loaded, name string) Application {
	for _, l := range loaded {
		if l.Name == name {
			return l.App
		}
	}
	return nil
}

// RegisterFlags registers every entry's own run arguments over the
// command's flag set, in table order — the walk the commands run when
// they build their surfaces.
func RegisterFlags(flags *pflag.FlagSet, args *Arguments) {
	for _, e := range Table {
		if e.RegisterFlags != nil {
			e.RegisterFlags(flags, args)
		}
	}
}

// Select resolves the applications the list names against the table: nil
// keeps the inference — an entry loads whose role bounds hold, whose
// requirements load, and whose required arguments are present, the
// zero-conf default; the empty list loads none, the deliberate core; a
// given list loads exactly the named entries, in table order whatever
// order the list spells. Every miscombination refuses, the fix named.
func Select(list []string, core bool, args Arguments) ([]Entry, error) {
	if list == nil {
		return infer(core, args), nil
	}
	return exact(list, core, args)
}

// infer loads every entry whose bounds and arguments hold, the
// requirements beside it loaded by the same rule.
func infer(core bool, args Arguments) []Entry {
	var loaded []Entry
	names := make(map[string]bool, len(Table))
	for _, e := range Table {
		if e.CoreOnly && !core || missingArg(e, &args) != "" {
			continue
		}
		beside := true
		for _, r := range e.Requires {
			beside = beside && names[r]
		}
		if !beside {
			continue
		}
		names[e.Name] = true
		loaded = append(loaded, e)
	}
	return loaded
}

// exact loads the named entries alone, refusing every miscombination with
// the fix named.
func exact(list []string, core bool, args Arguments) ([]Entry, error) {
	byName := make(map[string]Entry, len(Table))
	for _, e := range Table {
		byName[e.Name] = e
	}
	wanted := make(map[string]bool, len(list))
	for _, name := range list {
		if _, ok := byName[name]; !ok {
			return nil, fmt.Errorf("unknown application %q in --applications: "+
				"the residents are %s", name, residentNames())
		}
		wanted[name] = true
	}
	for _, e := range Table {
		if !wanted[e.Name] {
			continue
		}
		if e.CoreOnly && !core {
			return nil, fmt.Errorf("--applications names %s, which requires "+
				"the core role", e.Name)
		}
		if why := missingArg(e, &args); why != "" {
			return nil, fmt.Errorf("--applications names %s, whose loading "+
				"argument refuses it: %s", e.Name, why)
		}
		for _, r := range e.Requires {
			if !wanted[r] {
				return nil, fmt.Errorf("--applications names %s, which requires "+
					"%s beside it: requirements never imply, so name it in "+
					"the list too", e.Name, r)
			}
		}
	}
	var loaded []Entry
	for _, e := range Table {
		if wanted[e.Name] {
			loaded = append(loaded, e)
		}
	}
	return loaded, nil
}

// residentNames lists the table's names, comma-separated.
func residentNames() string {
	names := make([]string, 0, len(Table))
	for _, e := range Table {
		names = append(names, e.Name)
	}
	return strings.Join(names, ", ")
}

// missingArg reads the entry's refusal of its own loading; an entry
// without the check loads on any arguments.
func missingArg(e Entry, args *Arguments) string {
	if e.MissingArg == nil {
		return ""
	}
	return e.MissingArg(args)
}
