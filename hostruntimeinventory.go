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

// EnrichRuntimeInventory cooperatively observes cancellation. The CLI isolates this work in a bounded worker.
func (inv *HostInventory) EnrichRuntimeInventory(ctx context.Context) {
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

func (inv *HostInventory) enrichRuntimeInventory(ctx context.Context, read func(*os.File) runtimeModules) {
	r := inv.Runtime
	if r == nil || r.Status == "skipped" || r.enriched {
		return
	}
	r.enriched = true
	ctx, cancel := context.WithTimeout(ctx, runtimeBudget)
	defer cancel()
	if inv.FoundIn == nil {
		inv.FoundIn = map[string][]string{}
	}
	if inv.Paths == nil {
		inv.Paths = map[string]string{}
	}
	if inv.Fixes == nil {
		inv.Fixes = map[string]HostFix{}
	}
	if inv.EntrySource == nil {
		inv.EntrySource = map[string]string{}
	}
	if inv.GoBinaries == nil {
		inv.GoBinaries = map[string][]HostBinary{}
	}
	if inv.runtimePlaces == nil {
		inv.runtimePlaces = map[string]bool{}
	}
	h := &hostReader{root: "/", goos: runtime.GOOS, inv: *inv, seen: map[string]bool{}}
	for _, entry := range inv.Entries {
		h.seen[entry] = true
	}
	cache := map[string]runtimeInventoryResult{}
	labels := runtimeExecutableLabels(*inv)
	var entries []found
	var unassessed []HostComponent
	readCount, identified := 0, 0
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
			if readCount >= runtimeExecutableLimit {
				result.reason = "runtime executable count limit reached"
				break
			}
			readCount++
			mods, reason := readObservedModules(ctx, *p, read)
			result.reason = reason
			if reason != "" {
				break
			}
			place := p.Executable
			if label := labels[p.Executable]; label != "" {
				place = label
			}
			if existing, ok := h.inv.Paths[place]; ok && existing != p.Executable {
				result.reason = "executable path collides with an existing installation label"
				break
			}
			h.at(place, p.Executable)
			if place == p.Executable {
				h.inv.runtimePlaces[place] = true
			}
			h.fix(place, binaryFix(filepath.Base(p.Executable), p.Executable, mods.main))
			entries = append(entries, foundIn(place, mods.entries)...)
			if mods.goBinary {
				for _, entry := range mods.entries {
					binary := HostBinary{Path: p.Executable, Name: place}
					if !mods.renamed[entry] && !slices.Contains(h.inv.GoBinaries[entry], binary) {
						h.inv.GoBinaries[entry] = append(h.inv.GoBinaries[entry], binary)
					}
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
			unassessed = append(unassessed, HostComponent{Name: name, Reason: result.reason})
			if !strings.HasPrefix(result.reason, "no supported") {
				r.gap("inventory", p.PID, result.reason)
			}
		}
	}
	if len(r.Processes) > 0 {
		h.add(runtimeInventorySource, fmt.Sprintf("%d executable files identified, %d not assessed", identified, len(unassessed)), entries, unassessed)
	}
	h.inv.Note = h.note()
	*inv = h.inv
	inv.matchRuntime(ctx, r)
	r.normalize()
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
