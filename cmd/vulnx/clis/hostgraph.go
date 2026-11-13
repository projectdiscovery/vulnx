package clis

import (
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/projectdiscovery/vulnx/v2"
)

//go:embed hostgraph.html
var hostGraphPage string

// hostGraph is a host scan as a graph: the places things are installed in, the affected components found there
// and the advisories that affect them, each once, joined by index.
type hostGraph struct {
	OS      string           `json:"os"`
	Date    string           `json:"date"`
	Checked int              `json:"checked"`
	Places  []graphPlace     `json:"places"`
	Comps   []graphComponent `json:"comps"`
	Advs    []graphAdvisory  `json:"advs"`
	Risks   []vulnx.HostRisk `json:"risks"`
}

type graphPlace struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Fix    string `json:"fix,omitempty"` // how to update what is there
}

type graphComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"`
	Sev     string `json:"sev"`
	Mark    string `json:"mark,omitempty"` // KEV | POC
	Fixed   string `json:"fixed,omitempty"`
	Places  []int  `json:"places"`
	Advs    []int  `json:"advs"`
}

type graphAdvisory struct {
	ID   string  `json:"id"`
	Name string  `json:"name,omitempty"`
	Sev  string  `json:"sev"`
	CVSS float64 `json:"cvss,omitempty"`
	KEV  bool    `json:"kev,omitempty"`
	POC  bool    `json:"poc,omitempty"`
}

// buildHostGraph joins the scan's findings: a component a binary cannot reach is left out, as the grid leaves it.
func buildHostGraph(inv vulnx.HostInventory, res vulnx.StackResult, now time.Time) hostGraph {
	g := hostGraph{OS: inv.OS, Date: now.Format("2006-01-02"), Checked: len(inv.Entries), Risks: inv.Risks,
		Places: []graphPlace{}, Comps: []graphComponent{}, Advs: []graphAdvisory{}}
	places, advs := map[string]int{}, map[string]int{}
	for _, f := range findings(inv, res) {
		c := graphComponent{Name: f.name, Version: f.version, Source: f.source, Sev: f.worst, Mark: f.mark,
			Fixed: f.item.FixedVersion, Places: []int{}, Advs: []int{}}
		if c.Sev == "" {
			c.Sev = "unrated"
		}
		for _, p := range f.places {
			i, ok := places[p]
			if !ok {
				i = len(g.Places)
				places[p] = i
				fix := inv.Fixes[p]
				how := strings.TrimSpace(fix.Command + " " + fix.Target)
				if fix.Command == "" {
					how = fix.Note
				}
				g.Places = append(g.Places, graphPlace{Name: p, Source: f.source, Fix: how})
			}
			c.Places = append(c.Places, i)
		}
		for _, a := range f.item.AdvisoryRows {
			if a.Reachability == "not_reachable" {
				continue
			}
			id := a.CVE
			if id == "" {
				id = a.AdvisoryID
			}
			if id == "" {
				continue
			}
			i, ok := advs[id]
			if !ok {
				i = len(g.Advs)
				advs[id] = i
				adv := graphAdvisory{ID: id, Name: a.Name, Sev: a.Severity, CVSS: a.CvssScore}
				if adv.Sev == "" {
					adv.Sev = "unrated"
				}
				g.Advs = append(g.Advs, adv)
			}
			if a.Exploit != nil {
				g.Advs[i].KEV = g.Advs[i].KEV || a.Exploit.KnownExploited
				g.Advs[i].POC = g.Advs[i].POC || a.Exploit.PublicExploit
			}
			c.Advs = append(c.Advs, i)
		}
		g.Comps = append(g.Comps, c)
	}
	return g
}

// writeHostGraph writes the scan as one self-contained page (no network, nothing uploaded) named
// vulnx-host-<date>.graph.html in the working directory, replacing the same day's, and returns its absolute path.
func writeHostGraph(inv vulnx.HostInventory, res vulnx.StackResult) (string, error) {
	now := time.Now()
	abs, err := filepath.Abs("vulnx-host-" + now.Format("2006-01-02") + ".graph.html")
	if err != nil {
		return "", err
	}
	// json.Marshal writes < > and & as \u escapes, so the data cannot close its script element
	data, err := json.Marshal(buildHostGraph(inv, res, now))
	if err != nil {
		return "", err
	}
	return abs, os.WriteFile(abs, []byte(strings.Replace(hostGraphPage, "/*DATA*/", string(data), 1)), 0o644)
}
