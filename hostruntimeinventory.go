package vulnx

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

const runtimeInventorySource = "runtime binaries"
const runtimeExecutableLimit = 128
const runtimeExecutableSize = 512 << 20

type runtimeModules struct {
	entries  []string
	renamed  map[string]bool
	main     string
	goBinary bool
}

type runtimeInventoryResult struct {
	status, reason string
	image          os.FileInfo
	matches        []HostRuntimeMatch
}

func readRuntimeModules(reader io.ReaderAt) runtimeModules {
	if entries, renamed, main, ok := goModulesFrom(reader); ok {
		return runtimeModules{entries: entries, renamed: renamed, main: main, goBinary: true}
	}
	if entries, ok := rustCratesFrom(reader); ok {
		return runtimeModules{entries: entries}
	}
	return runtimeModules{}
}

func sameRuntimeFile(actual, expected os.FileInfo) bool {
	return actual != nil && expected != nil && actual.Mode().IsRegular() && actual.Mode() == expected.Mode() && os.SameFile(actual, expected) && actual.Size() == expected.Size() && actual.ModTime().Equal(expected.ModTime())
}

func sameRuntimeImage(path string, expected os.FileInfo) bool {
	actual, err := os.Stat(path)
	return err == nil && sameRuntimeFile(actual, expected)
}

// enrichRuntimeInventoryHere reads the observed executables in this process. Parsing a binary cannot be
// cancelled, so the CLI does this in the runtime worker, which is killed at its deadline.
func (inv *HostInventory) enrichRuntimeInventoryHere(ctx context.Context) {
	inv.enrichRuntimeInventory(ctx, func(f *os.File) runtimeModules { return readRuntimeModules(f) })
}

func readObservedModules(ctx context.Context, p HostProcess, read func(*os.File) runtimeModules) (runtimeModules, string) {
	if ctx.Err() != nil {
		return runtimeModules{}, "runtime inventory deadline reached"
	}
	if p.image == nil || p.image.Size() > runtimeExecutableSize {
		return runtimeModules{}, "executable identity unavailable or size limit exceeded"
	}
	f, err := os.Open(p.Executable)
	if err != nil {
		return runtimeModules{}, "executable metadata could not be opened: " + err.Error()
	}
	before, statErr := f.Stat()
	if statErr != nil || !sameRuntimeFile(before, p.image) {
		if err := f.Close(); err != nil {
			return runtimeModules{}, "executable handle could not be closed: " + err.Error()
		}
		return runtimeModules{}, "opened executable differs from the observed image"
	}
	mods := read(f)
	after, statErr := f.Stat()
	closeErr := f.Close()
	if closeErr != nil {
		return runtimeModules{}, "executable handle could not be closed: " + closeErr.Error()
	}
	if ctx.Err() != nil {
		return runtimeModules{}, "runtime inventory deadline reached"
	}
	if statErr != nil || !sameRuntimeFile(after, before) || !sameRuntimeImage(p.Executable, p.image) {
		return runtimeModules{}, "executable changed while reading embedded metadata"
	}
	if len(mods.entries) > 65536 {
		return runtimeModules{}, "embedded package count exceeds inventory limit"
	}
	if len(mods.entries) == 0 {
		return runtimeModules{}, "no supported embedded package versions; containing installation, if any, is separate evidence"
	}
	return mods, ""
}

// runtimeFound is one component found in an observed executable, at its place.
type runtimeFound struct {
	Entry string `json:"entry"`
	In    string `json:"in"`
}

// runtimeAdditions is what reading the observed executables adds to the inventory: their components, the places
// they were found at and how those are updated, the Go binaries for reachability, and what could not be read. It
// is all the worker sends back besides the runtime snapshot.
type runtimeAdditions struct {
	Found      []runtimeFound          `json:"found"`
	Paths      map[string]string       `json:"paths"`
	Fixes      map[string]HostFix      `json:"fixes"`
	GoBinaries map[string][]HostBinary `json:"go_binaries"`
	Places     []string                `json:"places"` // places only the runtime snapshot saw
	Unassessed []HostComponent         `json:"unassessed"`
	Detail     string                  `json:"detail"`
	Read       bool                    `json:"read"` // some process was looked at: the source is reported
}

// enrichRuntimeInventory reads the components of the observed executables and adds them to the inventory, then
// relates each process to the installations that contain it.
func (inv *HostInventory) enrichRuntimeInventory(ctx context.Context, read func(*os.File) runtimeModules) {
	r := inv.Runtime
	if r == nil || r.Status == "skipped" || r.enriched {
		return
	}
	inv.applyRuntimeAdditions(inv.runtimeAdditions(ctx, read))
	inv.matchRuntime(ctx, r)
	r.normalize()
}

func (inv *HostInventory) runtimeAdditions(ctx context.Context, read func(*os.File) runtimeModules) runtimeAdditions {
	r := inv.Runtime
	a := runtimeAdditions{Paths: map[string]string{}, Fixes: map[string]HostFix{}, GoBinaries: map[string][]HostBinary{}}
	cache := map[string]runtimeInventoryResult{}
	labels := runtimeExecutableLabels(*inv)
	reads, identified := 0, 0
	for i := range r.Processes {
		p := &r.Processes[i]
		p.Matches = []HostRuntimeMatch{}
		p.Installations = nil
		result := runtimeInventoryResult{status: "unassessed", image: p.image}
		switch {
		case p.Executable == "":
			result.reason = "no verified executable path"
		case ctx.Err() != nil:
			result.reason = "runtime inventory deadline reached"
		case !sameRuntimeImage(p.Executable, p.image):
			result.reason = "executable identity changed or could not be revalidated"
		default:
			if prior, ok := cache[p.Executable]; ok && sameRuntimeFile(prior.image, p.image) {
				p.Inventory, p.InventoryReason, p.Matches = prior.status, prior.reason, prior.matches
				continue
			}
			if reads >= runtimeExecutableLimit {
				result.reason = "runtime executable count limit reached"
				break
			}
			reads++
			mods, reason := readObservedModules(ctx, *p, read)
			result.reason = reason
			if reason != "" {
				break
			}
			place := p.Executable
			if label := labels[p.Executable]; label != "" {
				place = label
			}
			if existing, ok := inv.Paths[place]; ok && existing != p.Executable {
				result.reason = "executable path collides with an existing installation label"
				break
			}
			if _, ok := inv.Paths[place]; !ok {
				a.Paths[place] = p.Executable
				if place == p.Executable {
					a.Places = append(a.Places, place)
				}
			}
			if _, ok := inv.Fixes[place]; !ok {
				a.Fixes[place] = binaryFix(filepath.Base(p.Executable), p.Executable, mods.main)
			}
			for _, entry := range mods.entries {
				a.Found = append(a.Found, runtimeFound{entry, place})
				binary := HostBinary{Path: p.Executable, Name: place}
				if mods.goBinary && !mods.renamed[entry] && !slices.Contains(inv.GoBinaries[entry], binary) && !slices.Contains(a.GoBinaries[entry], binary) {
					a.GoBinaries[entry] = append(a.GoBinaries[entry], binary)
				}
			}
			result.status = "identified"
			result.matches = []HostRuntimeMatch{{Place: place, Components: slices.Clone(mods.entries)}}
			identified++
		}
		p.Inventory, p.InventoryReason, p.Matches = result.status, result.reason, result.matches
		if p.Matches == nil {
			p.Matches = []HostRuntimeMatch{}
		}
		if p.Executable != "" && sameRuntimeImage(p.Executable, p.image) {
			cache[p.Executable] = result
		}
		if result.status == "unassessed" {
			name := p.Executable
			if name == "" {
				name = fmt.Sprintf("process %d", p.PID)
			}
			a.Unassessed = append(a.Unassessed, HostComponent{Name: name, Reason: result.reason})
			if !strings.HasPrefix(result.reason, "no supported") {
				r.gap("inventory", p.PID, result.reason)
			}
		}
	}
	a.Read = len(r.Processes) > 0
	a.Detail = fmt.Sprintf("%d executable files identified, %d not assessed", identified, len(a.Unassessed))
	return a
}

// applyRuntimeAdditions adds what the observed executables carry to the inventory, under their own source; a
// place's path and update already known stand.
func (inv *HostInventory) applyRuntimeAdditions(a runtimeAdditions) {
	if inv.Runtime != nil {
		inv.Runtime.enriched = true
	}
	h := &hostReader{root: "/", goos: runtime.GOOS, inv: *inv, seen: map[string]bool{}}
	if h.inv.FoundIn == nil {
		h.inv.FoundIn = map[string][]string{}
	}
	if h.inv.Paths == nil {
		h.inv.Paths = map[string]string{}
	}
	if h.inv.Fixes == nil {
		h.inv.Fixes = map[string]HostFix{}
	}
	if h.inv.EntrySource == nil {
		h.inv.EntrySource = map[string]string{}
	}
	if h.inv.GoBinaries == nil {
		h.inv.GoBinaries = map[string][]HostBinary{}
	}
	if h.inv.runtimePlaces == nil {
		h.inv.runtimePlaces = map[string]bool{}
	}
	for _, e := range h.inv.Entries {
		h.seen[e] = true
	}
	for place, path := range a.Paths {
		h.at(place, path)
	}
	for place, fix := range a.Fixes {
		h.fix(place, fix)
	}
	for entry, binaries := range a.GoBinaries {
		for _, b := range binaries {
			if !slices.Contains(h.inv.GoBinaries[entry], b) {
				h.inv.GoBinaries[entry] = append(h.inv.GoBinaries[entry], b)
			}
		}
	}
	for _, place := range a.Places {
		h.inv.runtimePlaces[place] = true
	}
	if a.Read {
		found := make([]found, len(a.Found))
		for i, f := range a.Found {
			found[i].entry, found[i].in = f.Entry, f.In
		}
		h.add(runtimeInventorySource, a.Detail, found, a.Unassessed)
	}
	h.inv.Note = h.note()
	*inv = h.inv
}

// RefreshRuntimeMatches filters snapshot associations after inventory resolution without inspecting the host again.
func (inv *HostInventory) RefreshRuntimeMatches(ctx context.Context) {
	if inv.Runtime == nil || inv.Runtime.Status == "skipped" {
		return
	}
	available := map[string]bool{}
	for _, e := range inv.Entries {
		available[e] = true
	}
	for i := range inv.Runtime.Processes {
		if ctx.Err() != nil {
			inv.Runtime.gap("matching", 0, ctx.Err().Error())
			return
		}
		p := &inv.Runtime.Processes[i]
		var matches []HostRuntimeMatch
		for _, m := range p.Matches {
			components := []string{}
			for _, e := range m.Components {
				if available[e] {
					components = append(components, e)
				}
			}
			if len(components) > 0 {
				matches = append(matches, HostRuntimeMatch{Place: m.Place, Components: components})
			}
		}
		p.Matches = matches
		if p.Matches == nil {
			p.Matches = []HostRuntimeMatch{}
		}
	}
}

// Labels can be reused for display only when every recorded binary with that name has the same path.
func runtimeExecutableLabels(inv HostInventory) map[string]string {
	names := map[string]string{}
	ambiguous := map[string]bool{}
	for _, binaries := range inv.GoBinaries {
		for _, b := range binaries {
			if previous, ok := names[b.Name]; ok && previous != b.Path {
				ambiguous[b.Name] = true
			}
			names[b.Name] = b.Path
		}
	}
	labels := map[string]string{}
	for name, path := range names {
		if !ambiguous[name] && inv.Paths[name] == path && (labels[path] == "" || name < labels[path]) {
			labels[path] = name
		}
	}
	return labels
}

func runtimeWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
