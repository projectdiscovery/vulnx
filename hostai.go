package vulnx

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// aiSource is the HostSource name of what aiTools reads.
const aiSource = "ai tools"

// aiApps names the applications that are AI assistants, editors or model runtimes, by bundle identifier, and the
// NVD product of each where the bundle's short version is the version NVD records (checked against
// SecurityContext's product index). An empty product: known, with nothing exact to check it against.
var aiApps = map[string]string{
	"com.anthropic.claudefordesktop": "anthropic:claude_desktop",
	"com.todesktop.230313mzl4w4u92":  "anysphere:cursor",
	"com.electron.ollama":            "ollama:ollama",
	"dev.zed.Zed":                    "zed:zed",
	"com.openai.chat":                "",
	"com.openai.codex":               "",
	"ai.elementlabs.lmstudio":        "",
	"jan.ai.app":                     "",
	"com.exafunction.windsurf":       "",
	"com.t3tools.t3code":             "",
	"ai.elementlabs.bionic":          "",
	"ai.opencode.desktop":            "",
}

// aiExtensions names the NVD product of editor extensions by publisher.name, where the extension's version is the
// version NVD records. An empty product: an AI extension with nothing exact to check it against (one whose product
// also covers a plugin for another editor, numbered differently, is left empty: its ranges would not apply).
var aiExtensions = map[string]string{
	"anthropic.claude-code":             "anthropic:claude_code",
	"github.copilot-chat":               "microsoft:github_copilot_chat",
	"saoudrizwan.claude-dev":            "cline:cline",
	"rooveterinaryinc.roo-cline":        "roocode:roo_code",
	"sourcegraph.cody-ai":               "sourcegraph:cody",
	"github.copilot":                    "",
	"openai.chatgpt":                    "",
	"continue.continue":                 "",
	"codeium.codeium":                   "",
	"google.geminicodeassist":           "",
	"amazonwebservices.amazon-q-vscode": "",
	"kilocode.kilo-code":                "",
	"tabnine.tabnine-vscode":            "",
}

// standaloneCLIs are the agent and model command-line tools installed as a lone binary under a home.
var standaloneCLIs = []struct{ path, name string }{
	{".lmstudio/bin/lms", "lms (LM Studio CLI)"},
}

// aiTools reads the AI software a machine runs that no package manager lists: assistant and editor applications,
// agent command-line tools that update themselves, AI editor extensions, and the packages MCP servers are started
// from. Only names, versions and package specifiers are read from a configuration; environment values never are.
func (h *hostReader) aiTools() {
	var entries []found
	var notAssessed []HostComponent
	var parts []string
	add := func(n int, one, many string) {
		if n > 0 {
			parts = append(parts, count(n, one, many))
		}
	}

	apps := 0
	if h.goos == "darwin" {
		for _, b := range h.glob(append([]string{"Applications/*.app"}, h.inHomes("Applications/*.app")...)...) {
			info := appInfo(filepath.Join(b, "Contents", "Info.plist"))
			product, ok := aiApps[info["CFBundleIdentifier"]]
			if !ok {
				continue
			}
			apps++
			name, ver := strings.TrimSuffix(filepath.Base(b), ".app"), info["CFBundleShortVersionString"]
			if product == "" || ver == "" {
				notAssessed = append(notAssessed, HostComponent{Name: name, Version: ver})
				continue
			}
			h.at(name+".app", b)
			h.fix(name+".app", HostFix{Kind: "app", Target: name, Note: "update " + name})
			entries = append(entries, found{productCPE(product, ver), name + ".app"})
		}
	}
	add(apps, "application", "applications")

	clis := 0
	for _, dir := range h.glob(h.inHomes(".local/share/claude/versions")...) {
		if v := newestVersion(dir); v != "" {
			clis++
			label := h.label(dir)
			h.fix(label, HostFix{Kind: "binary", Command: "claude update"})
			entries = append(entries, found{productCPE("anthropic:claude_code", v), label})
		}
	}
	// an agent that keeps its own versions and has no product to check it against: read, and said so
	for _, dir := range h.glob(h.inHomes(".local/share/cursor-agent/versions")...) {
		if v := newestEntry(dir); v != "" {
			clis++
			notAssessed = append(notAssessed, HostComponent{Name: "cursor-agent", Version: v})
		}
	}
	// a command-line tool that is neither a Go nor a Rust binary and comes from no package manager: no reader
	// sees it, so it is named here rather than left out
	for _, cli := range standaloneCLIs {
		for _, path := range h.glob(h.inHomes(cli.path)...) {
			if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
				clis++
				notAssessed = append(notAssessed, HostComponent{Name: cli.name, Reason: "a standalone binary that names no version (" + h.label(path) + ")"})
			}
		}
	}
	add(clis, "agent CLI", "agent CLIs")

	exts := 0
	for _, dir := range h.glob(h.inHomes(".vscode/extensions", ".vscode-insiders/extensions", ".vscode-oss/extensions",
		".cursor/extensions", ".windsurf/extensions")...) {
		label := h.label(dir)
		for _, e := range editorExtensions(dir) {
			product, known := aiExtensions[e.id]
			if !known && !aiExtensionName.MatchString(e.display) {
				continue
			}
			exts++
			if product == "" {
				notAssessed = append(notAssessed, HostComponent{Name: e.id, Version: e.version})
				continue
			}
			h.fix(label, HostFix{Kind: "app", Note: "update the extension in the editor"})
			entries = append(entries, found{productCPE(product, e.version), label})
		}
	}
	add(exts, "editor extension", "editor extensions")

	servers := h.mcpServers()
	listed := map[string]bool{}
	for _, s := range servers {
		switch {
		case s.url != "": // reached over the network: nothing of it is installed here
		case s.purl != "":
			h.fix(s.config, HostFix{Kind: "system", Note: "pin a fixed version in the MCP server's command"})
			entries = append(entries, found{s.purl, s.config})
		case !listed[s.name+"\x00"+s.spec]: // the same server in two agents' configurations is one thing not checked
			listed[s.name+"\x00"+s.spec] = true
			notAssessed = append(notAssessed, HostComponent{Name: "MCP server " + s.name, Version: s.spec, Reason: s.reason})
		}
	}
	add(len(servers), "configured MCP server", "configured MCP servers")
	h.agentSurface(servers)

	// a package a harness loads into itself runs with everything the harness can do
	loaded := h.loadedPackages()
	for _, p := range loaded {
		h.inv.AgentSurface = append(h.inv.AgentSurface, HostAgentItem{Kind: "plugin", Name: p.spec, Where: p.config, Detail: "an npm package " + p.harness + " loads"})
		if p.purl != "" {
			h.fix(p.config, HostFix{Kind: "system", Note: "pin a fixed version in the plugin list"})
			entries = append(entries, found{p.purl, p.config})
			continue
		}
		notAssessed = append(notAssessed, HostComponent{Name: p.harness + " plugin " + p.spec, Reason: p.reason})
		h.risk(HostRisk{"unpinned", "plugin", p.spec, p.config, p.spec + " has no version pinned: a new release runs inside " + p.harness + " the next time it starts"})
	}
	add(len(loaded), "harness plugin", "harness plugins")

	h.add(aiSource, strings.Join(parts, ", "), entries, notAssessed)
}

var versionName = regexp.MustCompile(`^\d+(\.\d+)+$`)

// newestVersion is the highest dotted version among a directory's entries: a tool that updates itself keeps each
// version it downloaded there and runs the newest.
func newestVersion(dir string) string {
	list, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	best := ""
	for _, e := range list {
		if versionName.MatchString(e.Name()) && (best == "" || versionLess(best, e.Name())) {
			best = e.Name()
		}
	}
	return best
}

// newestEntry is the last of a directory's subdirectories by name: versions named by date sort in order.
func newestEntry(dir string) string {
	list, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	best := ""
	for _, e := range list {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") && e.Name() > best {
			best = e.Name()
		}
	}
	return best
}

func versionLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] != bs[i] {
			if len(as[i]) != len(bs[i]) {
				return len(as[i]) < len(bs[i])
			}
			return as[i] < bs[i]
		}
	}
	return len(as) < len(bs)
}

type editorExtension struct{ id, version, display string }

var aiExtensionName = regexp.MustCompile(`\b(AI|Copilot|ChatGPT|Claude|Codeium|Cody|Cline|Roo Code|Gemini|LLM)\b`)

// editorExtensions reads the extensions installed in an editor's extensions directory, each from its own
// package.json; a directory the editor has marked removed (.obsolete) is not installed.
func editorExtensions(dir string) []editorExtension {
	obsolete := map[string]bool{}
	if raw, err := os.ReadFile(filepath.Join(dir, ".obsolete")); err == nil {
		if err := json.Unmarshal(raw, &obsolete); err != nil {
			obsolete = map[string]bool{}
		}
	}
	list, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []editorExtension
	for _, e := range list {
		if !e.IsDir() || obsolete[e.Name()] {
			continue
		}
		var pkg struct{ Publisher, Name, Version, DisplayName string }
		raw, err := os.ReadFile(filepath.Join(dir, e.Name(), "package.json"))
		if err != nil || json.Unmarshal(raw, &pkg) != nil || pkg.Publisher == "" || pkg.Name == "" || pkg.Version == "" {
			continue
		}
		out = append(out, editorExtension{strings.ToLower(pkg.Publisher + "." + pkg.Name), pkg.Version, pkg.DisplayName})
	}
	return out
}

// mcpServer is a server an agent starts on this machine: the package it runs when its command names one.
type mcpServer struct {
	name, config string // its name in the configuration, and the configuration's label
	spec         string // the package specifier, when the command runs a package
	purl         string // set when the package and its version are both known
	reason       string // why there is no purl
	command      []string
	url          string // set for a server reached over the network
}

type tomlServer struct {
	name    string
	command []string
	url     string
}

var (
	tomlTable  = regexp.MustCompile(`^\[mcp_servers\.("[^"]+"|[A-Za-z0-9_-]+)\]$`)
	tomlString = regexp.MustCompile(`^(command|url)\s*=\s*"((?:[^"\\]|\\.)*)"`)
	tomlArgs   = regexp.MustCompile(`^args\s*=\s*\[(.*)\]`)
	tomlItem   = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
)

// tomlMCPServers reads the [mcp_servers.<name>] tables of a configuration: the command, its arguments written on
// one line, and whether the server has a url. Nothing else of the file is read (a sub-table such as its env is not).
func tomlMCPServers(text string) []tomlServer {
	var out []tomlServer
	cur := -1
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			cur = -1
			if m := tomlTable.FindStringSubmatch(line); m != nil {
				out = append(out, tomlServer{name: strings.Trim(m[1], `"`)})
				cur = len(out) - 1
			}
			continue
		}
		if cur < 0 {
			continue
		}
		if m := tomlString.FindStringSubmatch(line); m != nil {
			if m[1] == "url" {
				out[cur].url = m[2]
			} else {
				out[cur].command = append([]string{m[2]}, out[cur].command...)
			}
		} else if m := tomlArgs.FindStringSubmatch(line); m != nil {
			for _, a := range tomlItem.FindAllStringSubmatch(m[1], -1) {
				out[cur].command = append(out[cur].command, a[1])
			}
		}
	}
	return out
}

// runner is a command that fetches a package and runs it.
type runner struct {
	eco    string     // the ecosystem it fetches from
	words  [][]string // the subcommands that run a package; none: the command itself does
	valued []string   // flags that take a value
	from   []string   // flags whose value is the package
}

var pyRunnerValued = []string{"--with", "--python", "-p", "--index", "--index-url", "--default-index"}

var runners = map[string]runner{
	"npx":  {eco: "npm", valued: []string{"-c", "--call"}, from: []string{"-p", "--package"}},
	"bunx": {eco: "npm", from: []string{"-p", "--package"}},
	"pnpm": {eco: "npm", words: [][]string{{"dlx"}}, from: []string{"--package"}},
	"npm":  {eco: "npm", words: [][]string{{"exec"}, {"x"}}, from: []string{"-p", "--package"}},
	"bun":  {eco: "npm", words: [][]string{{"x"}}, from: []string{"-p", "--package"}},
	"uvx":  {eco: "pypi", valued: pyRunnerValued, from: []string{"--from"}},
	"uv":   {eco: "pypi", words: [][]string{{"tool", "run"}}, valued: pyRunnerValued, from: []string{"--from"}},
	"pipx": {eco: "pypi", words: [][]string{{"run"}}, valued: []string{"--python", "--pip-args"}, from: []string{"--spec"}},
}

// runnerPackage is the package a command line fetches and runs ("npx -y @scope/server@1.2.0 --flag" gives npm and
// "@scope/server@1.2.0"), or "" when the command is not a package runner or names a path or URL.
func runnerPackage(command []string) (eco, spec string) {
	r, ok := runners[filepath.Base(command[0])]
	if !ok {
		return "", ""
	}
	args := command[1:]
	if len(r.words) > 0 {
		matched := false
		for _, w := range r.words {
			if len(args) >= len(w) && slices.Equal(args[:len(w)], w) {
				args, matched = args[len(w):], true
				break
			}
		}
		if !matched {
			return "", ""
		}
	}
	first := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if name, value, has := strings.Cut(a, "="); has && slices.Contains(r.from, name) {
			spec = value
			break
		}
		if slices.Contains(r.from, a) && i+1 < len(args) {
			spec = args[i+1]
			break
		}
		if slices.Contains(r.valued, a) {
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		// the first plain word is the package, unless a later flag names it (uvx --from pkg tool: after the tool
		// name everything is the tool's own)
		first = a
		break
	}
	if spec == "" {
		spec = first
	}
	local := strings.HasPrefix(spec, ".") || strings.Contains(spec, ":") || strings.Contains(strings.TrimPrefix(spec, "@"), "/") && !strings.HasPrefix(spec, "@")
	if spec == "" || local {
		return "", ""
	}
	return r.eco, spec
}

var pinned = regexp.MustCompile(`^\d+\.\d+[0-9A-Za-z.+-]*$`)

// splitSpec is a package specifier's name and exact version ("" unless one is pinned: a tag, a range or nothing
// names whatever is newest).
func splitSpec(eco, spec string) (name, version string) {
	name = spec
	if eco == "pypi" {
		if n, v, ok := strings.Cut(spec, "=="); ok {
			name, version = n, v
		} else if i := strings.LastIndex(spec, "@"); i > 0 {
			name, version = spec[:i], spec[i+1:]
		}
		if i := strings.IndexAny(name, "[<>=!~ "); i > 0 {
			name = name[:i]
		}
	} else if i := strings.LastIndex(spec, "@"); i > 0 {
		name, version = spec[:i], spec[i+1:]
	}
	if !pinned.MatchString(version) {
		version = ""
	}
	return name, version
}

// npxCached is the version of a package in the runner's cache of the home a configuration is under, when exactly
// one is there: what the server last started as.
func (h *hostReader) npxCached(from, name string) string {
	home := from
	for home != h.root && home != "/" && home != "." {
		if _, err := os.Stat(filepath.Join(home, ".npm", "_npx")); err == nil {
			break
		}
		home = filepath.Dir(home)
	}
	versions := map[string]bool{}
	for _, p := range globAll(filepath.Join(home, ".npm", "_npx", "*", "node_modules", filepath.FromSlash(name), "package.json")) {
		var pkg struct{ Version string }
		if raw, err := os.ReadFile(p); err == nil && json.Unmarshal(raw, &pkg) == nil && pkg.Version != "" {
			versions[pkg.Version] = true
		}
	}
	if len(versions) != 1 {
		return ""
	}
	for v := range versions {
		return v
	}
	return ""
}

// stripJSONComments removes // and /* */ comments, then trailing commas, outside strings: editors' configuration
// files allow both.
func stripJSONComments(raw []byte) []byte {
	return outsideStrings(outsideStrings(raw, func(raw []byte, i int) (skip int, put byte) {
		switch {
		case raw[i] == '/' && i+1 < len(raw) && raw[i+1] == '/':
			n := bytes.IndexByte(raw[i:], '\n')
			if n < 0 {
				n = len(raw) - i
			}
			return n, 0
		case raw[i] == '/' && i+1 < len(raw) && raw[i+1] == '*':
			n := bytes.Index(raw[i+2:], []byte("*/"))
			if n < 0 {
				return len(raw) - i, 0
			}
			return n + 4, ' '
		}
		return 0, 0
	}), func(raw []byte, i int) (skip int, put byte) {
		if raw[i] != ',' {
			return 0, 0
		}
		rest := bytes.TrimLeft(raw[i+1:], " \t\r\n")
		if len(rest) > 0 && (rest[0] == '}' || rest[0] == ']') {
			return 1, 0
		}
		return 0, 0
	})
}

// outsideStrings copies raw, asking cut at each byte outside a JSON string how many bytes to leave out there
// (0: none) and what to put in their place (0: nothing).
func outsideStrings(raw []byte, cut func(raw []byte, i int) (skip int, put byte)) []byte {
	out := make([]byte, 0, len(raw))
	inString, escaped := false, false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		if skip, put := cut(raw, i); skip > 0 {
			if put != 0 {
				out = append(out, put)
			}
			i += skip - 1
			continue
		}
		inString = c == '"'
		out = append(out, c)
	}
	return out
}

var (
	rangeVersion    = regexp.MustCompile(`\d[0-9A-Za-z.+-]*`)
	calendarVersion = regexp.MustCompile(`^(19|20)\d\d\.\d{1,2}(\.|-|$)`)
)

var severityOrder = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// DropOtherSchemes removes, from a product's rows, the advisories whose every range bound is a date (2025.09.17)
// where the installed version is not: one product can cover two programs numbered differently (an editor at 3.29
// and its command-line agent at 2025.09.17), and a date bound compared with 3.29 reads affected whatever it says.
// An item left with no row is clean.
func (inv *HostInventory) DropOtherSchemes(res *StackResult) {
	for i := range res.Items {
		it := &res.Items[i]
		if !strings.HasPrefix(it.Input, "cpe:") || it.Status != "affected" || calendarVersion.MatchString(it.Version) {
			continue
		}
		kept := it.AdvisoryRows[:0]
		for _, row := range it.AdvisoryRows {
			bounds := rangeVersion.FindAllString(strings.Join(row.Ranges, " "), -1)
			other := len(bounds) > 0
			for _, b := range bounds {
				other = other && calendarVersion.MatchString(b)
			}
			if !other {
				kept = append(kept, row)
			}
		}
		dropped := len(it.AdvisoryRows) - len(kept)
		if dropped == 0 {
			continue
		}
		it.AdvisoryRows = kept
		it.Advisories -= dropped
		it.AdvisoryRowsTotal = max(it.AdvisoryRowsTotal-dropped, 0)
		it.WorstSeverity = ""
		for _, row := range kept {
			if severityOrder[row.Severity] > severityOrder[it.WorstSeverity] {
				it.WorstSeverity = row.Severity
			}
		}
		if len(kept) == 0 && it.Advisories <= 0 {
			it.Status, it.Advisories, it.FixedVersion, it.KnownExploited = "clean", 0, "", nil
			res.Summary.Affected--
			res.Summary.Clean++
		}
	}
}
