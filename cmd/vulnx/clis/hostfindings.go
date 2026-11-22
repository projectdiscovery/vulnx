package clis

// vulnx scan --host's findings: the affected components a program can reach, ranked, and the updates that fix them.

import (
	"net/url"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/projectdiscovery/vulnx/v2"
)

// componentParts splits a check entry into a kind, a name and a version for display, cleaned for the terminal.
func componentParts(entry string) (kind, name, version string) {
	kind, name, version = entryParts(entry)
	return termClean(kind), termClean(name), termClean(version)
}

func entryParts(entry string) (kind, name, version string) {
	if strings.HasPrefix(entry, "cpe:2.3:") {
		f := strings.Split(entry, ":")
		if len(f) > 5 {
			return "product", f[3] + ":" + f[4], strings.ReplaceAll(f[5], "\\", "")
		}
		return "product", entry, ""
	}
	body, _, _ := strings.Cut(strings.TrimPrefix(entry, "pkg:"), "?")
	typ, rest, _ := strings.Cut(body, "/")
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return typ, rest, ""
	}
	name, version = rest[:at], rest[at+1:]
	if u, err := url.PathUnescape(name); err == nil {
		name = u
	}
	if u, err := url.PathUnescape(version); err == nil {
		version = u
	}
	switch typ {
	case "golang":
		typ = "go"
	case "cargo":
		typ = "crate"
	case "deb", "rpm", "apk":
		name = name[strings.LastIndex(name, "/")+1:]
	}
	return typ, name, version
}

func advisoryCount(it vulnx.StackItem) int {
	if it.AdvisoryRowsTotal > it.Advisories {
		return it.AdvisoryRowsTotal
	}
	return it.Advisories
}

// unreachable is a host scan's Go item that no binary carrying it can run: each one was checked and links none of
// the functions its advisories name.
func unreachable(it vulnx.StackItem) bool {
	r := it.Reachability
	return r != nil && len(r.NotReachable) > 0 && len(r.Reachable) == 0 && len(r.Unknown) == 0
}

// liveSeverity is an item's worst severity and advisory count over the rows a binary can run (rows not marked
// not_reachable); without reachability marks, the API's own.
func liveSeverity(it vulnx.StackItem) (string, int) {
	worst, n, marked := "", 0, false
	for _, a := range it.AdvisoryRows {
		if a.Reachability == "not_reachable" {
			marked = true
			continue
		}
		n++
		if worst == "" || vulnx.WorseSeverity(a.Severity, worst) {
			worst = a.Severity
		}
	}
	if !marked {
		return it.WorstSeverity, advisoryCount(it)
	}
	return worst, n
}

// Tiers of what to update, most urgent first.
const (
	tierKEV     = iota // a known exploited CVE
	tierExploit        // critical or high, with a public exploit
	tierSevere         // critical or high
	tierRest           // medium and low
)

var tierTitles = []string{"Update now · known exploited", "Next · critical or high, public exploit",
	"Then · critical or high", "Later · medium and low"}

// finding is one affected component that some place carries and some binary can reach.
type finding struct {
	item                vulnx.StackItem
	kind, name, version string
	worst, mark         string
	tier                int
	source              string   // the source that counted it (HostSource.Name)
	places              []string // where it was found, less the binaries that link none of its affected code
}

// findings are a host scan's affected components, most urgent first.
func findings(inv vulnx.HostInventory, res vulnx.StackResult) []finding {
	var out []finding
	for _, it := range res.Items {
		if it.Status != "affected" || unreachable(it) {
			continue
		}
		f := finding{item: it, source: inv.EntrySource[it.Input]}
		f.kind, f.name, f.version = componentParts(it.Input)
		f.worst, _ = liveSeverity(it)
		for _, a := range it.AdvisoryRows {
			if a.Exploit == nil || a.Reachability == "not_reachable" {
				continue
			}
			if a.Exploit.KnownExploited {
				f.mark = "KEV"
			} else if a.Exploit.PublicExploit && f.mark == "" {
				f.mark = "POC"
			}
		}
		severe := f.worst == "critical" || f.worst == "high"
		switch {
		case f.mark == "KEV":
			f.tier = tierKEV
		case severe && f.mark == "POC":
			f.tier = tierExploit
		case severe:
			f.tier = tierSevere
		default:
			f.tier = tierRest
		}
		for _, p := range inv.FoundIn[it.Input] {
			if it.Reachability == nil || !slices.Contains(it.Reachability.NotReachable, p) {
				f.places = append(f.places, p)
			}
		}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].tier != out[j].tier {
			return out[i].tier < out[j].tier
		}
		return vulnx.WorseSeverity(out[i].worst, out[j].worst)
	})
	return out
}

// label is a component's name as a report says it: a product without its vendor, a Go module without its host,
// the Go standard library by name.
func (f finding) label() string {
	switch {
	case f.kind == "product":
		if f.name == "apple:macos" {
			return "macOS"
		}
		_, name, _ := strings.Cut(f.name, ":")
		return strings.ReplaceAll(name, "_", " ")
	case f.kind == "go" && f.name == "stdlib":
		return "Go stdlib"
	case f.kind == "go":
		for _, host := range []string{"github.com/", "golang.org/", "google.golang.org/", "gopkg.in/"} {
			if strings.HasPrefix(f.name, host) {
				return strings.TrimPrefix(f.name, host)
			}
		}
	}
	return f.name
}

// short is the component with its version and fix ("lxml 4.9.3 → 6.1.0"); a pseudo-version is cut.
func (f finding) short() string {
	s := f.label() + " " + fit(f.version, 20)
	if f.item.FixedVersion != "" {
		s += " → " + fit(f.item.FixedVersion, 20)
	}
	return s
}

// hostAction is one thing to do: a command and the names it takes (brew upgrade php mitmproxy), or a note.
type hostAction struct {
	tier    int
	fix     vulnx.HostFix
	targets []string            // what the command names, in urgency order; one note target with no command
	why     map[string][]string // target -> the components that make it urgent
	worst   string
}

// program is the name a reason line starts with: the formula or tool a target updates (none for a note naming it).
func (a hostAction) program(target string) string {
	switch a.fix.Kind {
	case "brew", "cargo":
		return termClean(target)
	case "go-install":
		return termClean(path.Base(strings.TrimSuffix(target, "@latest")))
	}
	return ""
}

// line is the action as typed or read: the command with its names, each quoted for the shell, or the note.
func (a hostAction) line() string {
	if a.fix.Command == "" {
		return termClean(a.fix.Note)
	}
	if a.fix.Kind == "npm" { // a global tool's dependency is updated with the tool: npm update -g takes no names
		return termClean(a.fix.Command)
	}
	quoted := make([]string, len(a.targets))
	for i, t := range a.targets {
		quoted[i] = vulnx.ShellQuote(t)
	}
	return termClean(a.fix.Command + " " + strings.Join(quoted, " "))
}

// hostActions turns findings into updates: each place's fix, named once at its most urgent tier.
func hostActions(inv vulnx.HostInventory, fs []finding) []hostAction {
	type key struct{ kind, command, note string }
	type target struct {
		key  key
		fix  vulnx.HostFix
		name string
	}
	tierOf := map[target]int{}
	why := map[target][]string{}
	worst := map[target]string{}
	var order []target
	for _, f := range fs {
		for _, p := range f.places {
			fix, ok := inv.Fixes[p]
			if !ok {
				fix = vulnx.HostFix{Kind: "other", Note: "update what is in " + p}
			}
			name := fix.Target
			if name == "" {
				name = f.name
			}
			k := key{fix.Kind, fix.Command, ""}
			switch {
			case fix.Kind == "go-install" || (fix.Command == "" && fix.Target != ""): // one program a line
				k.note = fix.Note + "|" + name
			case fix.Command == "": // a note naming no program (Software Update): its components together
				k.note = fix.Note
			}
			t := target{k, fix, name}
			if prev, seen := tierOf[t]; !seen {
				tierOf[t] = f.tier
				worst[t] = f.worst
				order = append(order, t)
			} else if f.tier < prev {
				tierOf[t] = f.tier
			}
			if vulnx.WorseSeverity(f.worst, worst[t]) {
				worst[t] = f.worst
			}
			reason := f.short()
			if fix.Kind == "brew" || fix.Kind == "go-install" || fix.Kind == "cargo" || fix.Kind == "binary" {
				reason = f.label() // a formula or tool: which of its components
			}
			if !slices.Contains(why[t], reason) {
				why[t] = append(why[t], reason)
			}
		}
	}
	// an update that names nothing (Software Update, npm update -g) is made once, at its most urgent tier
	once := map[key]int{}
	for _, t := range order {
		if t.fix.Kind == "npm" || (t.fix.Command == "" && t.fix.Target == "") {
			if prev, ok := once[t.key]; !ok || tierOf[t] < prev {
				once[t.key] = tierOf[t]
			}
		}
	}
	for _, t := range order {
		if tier, ok := once[t.key]; ok {
			tierOf[t] = tier
		}
	}
	type group struct {
		tier int
		key  key
	}
	byGroup := map[group]*hostAction{}
	var out []*hostAction
	for _, t := range order {
		g := group{tierOf[t], t.key}
		a := byGroup[g]
		if a == nil {
			a = &hostAction{tier: g.tier, fix: t.fix, why: map[string][]string{}, worst: worst[t]}
			byGroup[g] = a
			out = append(out, a)
		}
		a.targets = append(a.targets, t.name)
		a.why[t.name] = why[t]
		if vulnx.WorseSeverity(worst[t], a.worst) {
			a.worst = worst[t]
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].tier != out[j].tier {
			return out[i].tier < out[j].tier
		}
		return actionRank(out[i].fix.Kind) < actionRank(out[j].fix.Kind)
	})
	actions := make([]hostAction, len(out))
	for i, a := range out {
		actions[i] = *a
	}
	return actions
}

// actionRank orders a tier's actions: the system first, then package managers, then programs one by one.
func actionRank(kind string) int {
	return slices.Index([]string{"macos", "apt", "dnf", "apk", "app", "brew", "pip", "npm", "gem", "go-install", "cargo",
		"binary", "system", "pin", "other"}, kind)
}
