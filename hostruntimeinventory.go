package vulnx

import (
	"context"
	"fmt"
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
}

func readRuntimeModules(path string) runtimeModules {
	if entries, renamed, main, ok := goModules(path); ok {
		return runtimeModules{entries: entries, renamed: renamed, main: main, goBinary: true}
	}
	if entries, ok := rustCrates(path); ok {
		return runtimeModules{entries: entries}
	}
	return runtimeModules{}
}

func sameRuntimeImage(path string, expected os.FileInfo) bool {
	if expected == nil {
		return false
	}
	actual, err := os.Stat(path)
	return err == nil && actual.Mode().IsRegular() && actual.Mode() == expected.Mode() && os.SameFile(actual, expected) && actual.Size() == expected.Size() && actual.ModTime().Equal(expected.ModTime())
}

// EnrichRuntimeInventory reads embedded identifiers without starting the observed executable.
func (inv *HostInventory) EnrichRuntimeInventory(ctx context.Context) {
	inv.enrichRuntimeInventory(ctx, readRuntimeModules)
}

func (inv *HostInventory) enrichRuntimeInventory(ctx context.Context, read func(string) runtimeModules) {
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
	var entries []found
	var unassessed []HostComponent
	readCount, identified := 0, 0
	for i := range r.Processes {
		p := &r.Processes[i]
		path := p.Executable
		if path == "" {
			p.Inventory, p.InventoryReason = "unassessed", "no verified executable path"
			unassessed = append(unassessed, HostComponent{Name: fmt.Sprintf("process %d", p.PID), Reason: p.InventoryReason})
			continue
		}
		if !sameRuntimeImage(path, p.image) {
			p.Inventory, p.InventoryReason = "unassessed", "executable identity changed or could not be revalidated"
			p.Matches = []HostRuntimeMatch{}
			p.Installations = nil
			r.gap("inventory", p.PID, p.InventoryReason)
			unassessed = append(unassessed, HostComponent{Name: fmt.Sprintf("process %d: %s", p.PID, path), Reason: p.InventoryReason})
			continue
		}
		if prior, ok := cache[path]; ok && sameRuntimeImage(path, prior.image) {
			p.Inventory, p.InventoryReason = prior.status, prior.reason
			continue
		}
		result := runtimeInventoryResult{status: "unassessed", image: p.image}
		switch {
		case ctx.Err() != nil:
			result.reason = "runtime inventory deadline reached"
		case len(p.Matches) > 0:
			result.status = "inventoried"
		case readCount >= runtimeExecutableLimit:
			result.reason = "runtime executable count limit reached"
		case p.image.Size() > runtimeExecutableSize:
			result.reason = "executable exceeds metadata-reading size limit"
		default:
			readCount++
			file, err := os.Open(path)
			if err != nil {
				result.reason = "executable metadata could not be opened: " + err.Error()
				break
			}
			if err := file.Close(); err != nil {
				result.reason = "executable metadata handle could not be closed: " + err.Error()
				break
			}
			mods := read(path)
			if ctx.Err() != nil {
				result.reason = "runtime inventory deadline reached"
			} else if !sameRuntimeImage(path, p.image) {
				result.reason = "executable changed while reading embedded metadata"
			} else if len(mods.entries) > 65536 {
				result.reason = "embedded package count exceeds inventory limit"
			} else if len(mods.entries) == 0 {
				result.reason = "no supported embedded package versions; containing installation, if any, is separate evidence"
			} else {
				result.status = "identified"
				identified++
				place := path
				if existing, ok := h.inv.Paths[place]; ok && existing != path {
					result.status, result.reason = "unassessed", "executable path collides with an existing installation label"
					identified--
				} else {
					h.at(place, path)
					h.inv.runtimePlaces[place] = true
					h.fix(place, binaryFix(filepath.Base(path), path, mods.main))
					entries = append(entries, foundIn(place, mods.entries)...)
					if mods.goBinary {
						for _, entry := range mods.entries {
							binary := HostBinary{Path: path, Name: place}
							if !mods.renamed[entry] && !slices.Contains(h.inv.GoBinaries[entry], binary) {
								h.inv.GoBinaries[entry] = append(h.inv.GoBinaries[entry], binary)
							}
						}
					}
				}
			}
		}
		p.Inventory, p.InventoryReason = result.status, result.reason
		cache[path] = result
		if result.status == "unassessed" {
			unassessed = append(unassessed, HostComponent{Name: path, Reason: result.reason})
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
	inv.RefreshRuntimeMatches(ctx)
}

// RefreshRuntimeMatches preserves the original observation times; it does not collect sockets again.
func (inv *HostInventory) RefreshRuntimeMatches(ctx context.Context) {
	if inv.Runtime == nil || inv.Runtime.Status == "skipped" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, runtimeBudget)
	defer cancel()
	inv.matchRuntime(ctx, inv.Runtime)
	inv.Runtime.normalize()
}

func runtimeWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
