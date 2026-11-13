package vulnx

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// HostRuntime contains observations, not a verdict about external access or exploitability.
type HostRuntime struct {
	StartedAt  string           `json:"started_at"`
	FinishedAt string           `json:"finished_at"`
	Status     string           `json:"status"`
	Scope      string           `json:"scope"`
	Endpoints  []HostEndpoint   `json:"endpoints"`
	Processes  []HostProcess    `json:"processes"`
	Gaps       []HostRuntimeGap `json:"gaps"`
	enriched   bool
}

type HostEndpoint struct {
	Protocol string `json:"protocol"`
	Family   string `json:"family"`
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	Bind     string `json:"bind"`
	State    string `json:"state"`
	Owners   []int  `json:"owners"`
	Socket   string `json:"socket,omitempty"`
}

type HostProcess struct {
	PID             int                       `json:"pid"`
	UID             *uint32                   `json:"uid,omitempty"`
	EffectiveUID    *uint32                   `json:"effective_uid,omitempty"`
	Identity        string                    `json:"identity,omitempty"`
	Executable      string                    `json:"executable,omitempty"`
	Matches         []HostRuntimeMatch        `json:"matches"`
	Installations   []HostRuntimeInstallation `json:"installations,omitempty"`
	Inventory       string                    `json:"inventory,omitempty"`
	InventoryReason string                    `json:"inventory_reason,omitempty"`
	image           os.FileInfo
}

// HostRuntimeMatch establishes an executable's inventory identity, not its loaded dependencies.
type HostRuntimeMatch struct {
	Place      string   `json:"place"`
	Components []string `json:"components"`
}

// HostRuntimeInstallation records directory containment, not loaded components.
type HostRuntimeInstallation struct {
	Place    string `json:"place"`
	Path     string `json:"path"`
	Relation string `json:"relation"`
}

type HostRuntimeGap struct {
	Stage  string `json:"stage"`
	PID    int    `json:"pid,omitempty"`
	Reason string `json:"reason"`
}

const runtimeBudget = 10 * time.Second

// CollectRuntime never inspects the scanning host for a mounted-filesystem inventory.
func (inv *HostInventory) CollectRuntime(ctx context.Context, root string) {
	inv.collectRuntime(ctx, root, collectHostRuntime)
}

func (inv *HostInventory) collectRuntime(ctx context.Context, root string, collect func(context.Context, *HostRuntime)) {
	r := &HostRuntime{StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Status: "collected", Endpoints: []HostEndpoint{}, Processes: []HostProcess{}, Gaps: []HostRuntimeGap{}}
	inv.Runtime = r
	if root != "" && filepath.Clean(root) != "/" {
		r.Status, r.Scope = "skipped", "mounted filesystem; no live runtime inspected"
	} else {
		bounded, cancel := context.WithTimeout(ctx, runtimeBudget)
		defer cancel()
		if bounded.Err() == nil {
			collect(bounded, r)
		}
		if bounded.Err() != nil {
			r.gap("collection", 0, bounded.Err().Error())
		}
		inv.matchRuntime(bounded, r)
	}
	r.normalize()
	r.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
}

func (r *HostRuntime) gap(stage string, pid int, reason string) {
	if r.Status != "unavailable" && r.Status != "skipped" {
		r.Status = "partial"
	}
	if len(r.Gaps) >= 512 {
		if len(r.Gaps) == 512 {
			r.Gaps = append(r.Gaps, HostRuntimeGap{Stage: "collection", Reason: "additional collection gaps omitted after limit"})
		}
		return
	}
	g := HostRuntimeGap{Stage: stage, PID: pid, Reason: reason}
	if !slices.Contains(r.Gaps, g) {
		r.Gaps = append(r.Gaps, g)
	}
}

func runtimeBind(address string) string {
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return "unknown"
	}
	ip = ip.Unmap()
	if ip.IsLoopback() {
		return "loopback"
	}
	if ip.IsUnspecified() {
		return "wildcard"
	}
	return "specific_address"
}

func runtimePath(path string) string {
	if !filepath.IsAbs(path) || strings.HasSuffix(path, " (deleted)") {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return ""
	}
	st, err := os.Stat(resolved)
	if err != nil || !st.Mode().IsRegular() {
		return ""
	}
	return resolved
}

func (inv HostInventory) matchRuntime(ctx context.Context, r *HostRuntime) {
	for i := range r.Processes {
		r.Processes[i].Matches = []HostRuntimeMatch{}
		r.Processes[i].Installations = nil
	}
	var roots []HostRuntimeInstallation
	for place, path := range inv.Paths {
		if ctx.Err() != nil {
			r.gap("matching", 0, "installation indexing deadline reached")
			return
		}
		if !filepath.IsAbs(path) {
			continue
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			continue
		}
		if st, err := os.Stat(resolved); err == nil && st.IsDir() && resolved != string(filepath.Separator) {
			roots = append(roots, HostRuntimeInstallation{Place: place, Path: resolved, Relation: "contained_in"})
		}
	}
	slices.SortFunc(roots, func(a, b HostRuntimeInstallation) int {
		if n := strings.Compare(a.Place, b.Place); n != 0 {
			return n
		}
		return strings.Compare(a.Path, b.Path)
	})
	byPath := map[string]map[string][]string{}
	cache := map[string]string{}
	resolve := func(path string) string {
		if resolved, ok := cache[path]; ok {
			return resolved
		}
		resolved := runtimePath(path)
		cache[path] = resolved
		return resolved
	}
	add := func(path, place, component string) {
		if ctx.Err() != nil {
			return
		}
		path = resolve(path)
		if path == "" {
			return
		}
		if byPath[path] == nil {
			byPath[path] = map[string][]string{}
		}
		if !slices.Contains(byPath[path][place], component) {
			byPath[path][place] = append(byPath[path][place], component)
		}
	}
	for component, places := range inv.FoundIn {
		if ctx.Err() != nil {
			r.gap("matching", 0, "collection deadline reached before inventory indexing completed")
			return
		}
		for _, place := range places {
			if path := inv.Paths[place]; path != "" {
				add(path, place, component)
			}
		}
	}
	for component, binaries := range inv.GoBinaries {
		if ctx.Err() != nil {
			r.gap("matching", 0, "collection deadline reached before inventory indexing completed")
			return
		}
		for _, binary := range binaries {
			add(binary.Path, binary.Name, component)
		}
	}
	for i := range r.Processes {
		if ctx.Err() != nil {
			r.gap("matching", 0, "collection deadline reached before executable matching completed")
			return
		}
		p := &r.Processes[i]
		if p.Executable == "" {
			continue
		}
		if !sameRuntimeImage(p.Executable, p.image) {
			r.gap("matching", p.PID, "observed executable no longer matches on-disk identity")
			continue
		}
		if path := runtimePath(p.Executable); path != "" {
			for _, root := range roots {
				if runtimeWithin(root.Path, path) {
					p.Installations = append(p.Installations, root)
				}
			}
			for place, components := range byPath[path] {
				slices.Sort(components)
				p.Matches = append(p.Matches, HostRuntimeMatch{Place: place, Components: components})
			}
		}
		slices.SortFunc(p.Matches, func(a, b HostRuntimeMatch) int { return strings.Compare(a.Place, b.Place) })
	}
}

func (r *HostRuntime) normalize() {
	for i := range r.Endpoints {
		e := &r.Endpoints[i]
		e.Bind = runtimeBind(e.Address)
		if e.Owners == nil {
			e.Owners = []int{}
		}
		slices.Sort(e.Owners)
		e.Owners = slices.Compact(e.Owners)
	}
	slices.SortFunc(r.Endpoints, func(a, b HostEndpoint) int {
		for _, pair := range [][2]string{{a.Protocol, b.Protocol}, {a.Family, b.Family}, {a.Address, b.Address}, {a.Socket, b.Socket}} {
			if n := strings.Compare(pair[0], pair[1]); n != 0 {
				return n
			}
		}
		return int(a.Port) - int(b.Port)
	})
	out := r.Endpoints[:0]
	for _, e := range r.Endpoints {
		if len(out) > 0 {
			last := &out[len(out)-1]
			if last.Protocol == e.Protocol && last.Family == e.Family && last.Address == e.Address && last.Port == e.Port && last.Socket == e.Socket {
				last.Owners = append(last.Owners, e.Owners...)
				slices.Sort(last.Owners)
				last.Owners = slices.Compact(last.Owners)
				continue
			}
		}
		out = append(out, e)
	}
	r.Endpoints = out
	slices.SortFunc(r.Processes, func(a, b HostProcess) int { return a.PID - b.PID })
	slices.SortFunc(r.Gaps, func(a, b HostRuntimeGap) int {
		if n := strings.Compare(a.Stage, b.Stage); n != 0 {
			return n
		}
		if a.PID != b.PID {
			return a.PID - b.PID
		}
		return strings.Compare(a.Reason, b.Reason)
	})
}
