package vulnx

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// HostAgentItem is one thing a coding agent or an editor loads and runs for the user.
type HostAgentItem struct {
	Kind    string `json:"kind"` // extension, skill, plugin, hook, mcp_server, model, runtime
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Where   string `json:"where"`            // the directory or configuration it is in
	Detail  string `json:"detail,omitempty"` // an MCP server's package or host, a hook's event
}

// HostRisk is a fact about how one of them is set up that lets someone else decide what runs on this machine. It
// is read from the files: a risk, never a verdict that the thing is hostile.
type HostRisk struct {
	Risk   string `json:"risk"` // removed_malware, removed, unpinned, unverified_source, plaintext, sideloaded, lookalike, pipe_to_shell, hidden_text, approvals_off
	Kind   string `json:"kind"` // HostAgentItem.Kind, or agent
	Name   string `json:"name"`
	Where  string `json:"where"`
	Detail string `json:"detail"`
}

// RiskText says each risk in a few words, for a count line.
var RiskText = map[string]string{
	"removed_malware":     "removed from a marketplace as malware",
	"removed":             "removed from a marketplace as an impersonation or untrustworthy",
	"unpinned":            "run whatever version is newest at each start",
	"unverified_source":   "fetched from a git URL or a non-default registry",
	"plaintext":           "reached over unencrypted http",
	"sideloaded":          "installed from a file, not a marketplace",
	"lookalike":           "named like a well-known extension from another publisher",
	"pipe_to_shell":       "download code and run it",
	"hidden_text":         "carry invisible characters in their instructions",
	"approvals_off":       "run commands without asking",
	"model_runs_commands": "import command-running code when loaded",
	"exposed":             "set to listen beyond this machine with no login",
	"pickle_format":       "in a format that can run code when loaded (pickle)",
	"custom_code":         "ship their own code, run when loaded with remote code trusted",
}

// knownExtensions names the publisher of extensions whose name is copied to deceive ("python" from anyone but
// ms-python). anysphere republishes several for its own editor.
var knownExtensions = map[string]string{
	"python": "ms-python", "vscode-pylance": "ms-python", "debugpy": "ms-python", "cpptools": "ms-vscode",
	"cmake-tools": "ms-vscode", "remote-ssh": "ms-vscode-remote", "remote-containers": "ms-vscode-remote",
	"vscode-docker": "ms-azuretools", "csharp": "ms-dotnettools", "vscode-eslint": "dbaeumer",
	"prettier-vscode": "esbenp", "go": "golang", "rust-analyzer": "rust-lang", "gitlens": "eamodio",
	"java": "redhat", "vscode-yaml": "redhat", "solidity": "juanblanco", "liveserver": "ritwickdey",
	"material-icon-theme": "pkief", "code-runner": "formulahendry", "vscode-tailwindcss": "bradlc",
	"copilot": "github", "copilot-chat": "github", "claude-code": "anthropic", "claude-dev": "saoudrizwan",
	"continue": "continue", "volar": "vue", "terraform": "hashicorp", "vscode-kubernetes-tools": "ms-kubernetes-tools",
}

func (h *hostReader) risk(r HostRisk) { h.inv.Risks = append(h.inv.Risks, r) }

// agentSurface lists what agents and editors load on this machine and the risks in how each is set up.
func (h *hostReader) agentSurface(servers []mcpServer) {
	for _, dir := range h.glob(h.inHomes(".vscode/extensions", ".vscode-insiders/extensions", ".vscode-oss/extensions",
		".cursor/extensions", ".windsurf/extensions")...) {
		label := h.label(dir)
		fromFile := sideloaded(dir)
		for _, e := range editorExtensions(dir) {
			h.inv.AgentSurface = append(h.inv.AgentSurface, HostAgentItem{Kind: "extension", Name: e.id, Version: e.version, Where: label})
			publisher, name, _ := strings.Cut(e.id, ".")
			entry := "pkg:vscode-extension/" + url.PathEscape(publisher) + "/" + url.PathEscape(name) + "@" + url.PathEscape(e.version)
			if !slices.Contains(h.inv.Extensions, entry) {
				h.inv.Extensions = append(h.inv.Extensions, entry)
			}
			if !slices.Contains(h.inv.FoundIn[entry], label) {
				h.inv.FoundIn[entry] = append(h.inv.FoundIn[entry], label)
			}
			if owner, ok := knownExtensions[name]; ok && publisher != owner && publisher != "anysphere" {
				h.risk(HostRisk{"lookalike", "extension", e.id, label, "the well-known " + name + " extension is published by " + owner})
			}
			if fromFile[e.id] {
				h.risk(HostRisk{"sideloaded", "extension", e.id, label, "installed from a .vsix file: no marketplace reviewed or can withdraw it"})
			}
		}
	}

	for _, s := range servers {
		item := HostAgentItem{Kind: "mcp_server", Name: s.name, Where: s.config}
		if s.url != "" {
			u, err := url.Parse(s.url)
			if err == nil {
				item.Detail = "remote: " + u.Host
				if u.Scheme == "http" && !loopback(u.Hostname()) {
					h.risk(HostRisk{"plaintext", "mcp_server", s.name, s.config, "http://" + u.Host + ": anyone on the path can change what the server answers"})
				}
			}
			h.inv.AgentSurface = append(h.inv.AgentSurface, item)
			continue
		}
		eco, spec := runnerPackage(s.command)
		switch {
		case eco != "":
			item.Detail = eco + " package " + spec
			if _, version := splitSpec(eco, spec); version == "" {
				h.risk(HostRisk{"unpinned", "mcp_server", s.name, s.config, spec + " has no version pinned: a new release runs here the next time the agent starts"})
			}
		case runners[filepath.Base(s.command[0])].eco != "" && remoteSpec(s.command):
			item.Detail = "fetched by " + filepath.Base(s.command[0])
		default:
			item.Detail = "program " + filepath.Base(s.command[0])
		}
		if src := unverifiedSource(s.command); src != "" {
			h.risk(HostRisk{"unverified_source", "mcp_server", s.name, s.config, src})
		}
		h.inv.AgentSurface = append(h.inv.AgentSurface, item)
	}

	h.skills()
	h.hooks()
	h.approvals()
	if h.inv.Risks == nil {
		h.inv.Risks = []HostRisk{} // the report says "none found", not "not looked for"
	}
}

// sideloaded is the extensions an editor recorded as installed from a file (extensions.json, metadata.source).
func sideloaded(dir string) map[string]bool {
	var list []struct {
		Identifier struct{ ID string }
		Metadata   struct{ Source string }
	}
	out := map[string]bool{}
	raw, err := readCapped(filepath.Join(dir, "extensions.json"), maxConfigFile)
	if err != nil || json.Unmarshal(raw, &list) != nil {
		return out
	}
	for _, e := range list {
		if e.Metadata.Source == "vsix" {
			out[strings.ToLower(e.Identifier.ID)] = true
		}
	}
	return out
}

var (
	gitSpec       = regexp.MustCompile(`^(git\+|github:|gitlab:|bitbucket:|git@|https?://|ssh://)`)
	registryFlag  = regexp.MustCompile(`^--(registry|index-url|extra-index-url|index|default-index)(=(.*))?$`)
	knownRegistry = regexp.MustCompile(`^https://(registry\.npmjs\.org|registry\.yarnpkg\.com|pypi\.org)(/|$)`)
)

// remoteSpec reports a package runner given a git or URL source instead of a package name.
func remoteSpec(command []string) bool {
	return slices.ContainsFunc(command[1:], gitSpec.MatchString)
}

// unverifiedSource says where a package runner's command fetches from when that is a git or URL source or a
// registry other than the ecosystem's own; "" otherwise. The source's host is named, never its credentials.
func unverifiedSource(command []string) string {
	if runners[filepath.Base(command[0])].eco == "" {
		return ""
	}
	args := command[1:]
	for i, a := range args {
		if m := registryFlag.FindStringSubmatch(a); m != nil {
			value := m[3]
			if m[2] == "" && i+1 < len(args) {
				value = args[i+1]
			}
			if value != "" && !knownRegistry.MatchString(value) {
				return "fetched from the registry " + hostOf(value) + ", not the ecosystem's own"
			}
		}
		if gitSpec.MatchString(a) {
			return "fetched from " + hostOf(a) + ": whatever that source holds when the agent starts"
		}
	}
	return ""
}

func hostOf(source string) string {
	if u, err := url.Parse(strings.TrimPrefix(source, "git+")); err == nil && u.Host != "" {
		return u.Host
	}
	if scheme, rest, ok := strings.Cut(source, ":"); ok && !strings.Contains(scheme, "/") {
		return scheme + ":" + strings.SplitN(rest, "#", 2)[0]
	}
	return "another source"
}

var (
	// a download handed straight to an interpreter, a decoded blob handed to one, or a shell wired to a socket
	pipeToShell = regexp.MustCompile(`\b(curl|wget)\b[^\n|;&]*\|\s*((env|sudo)\s+)?(sh|bash|zsh|python3?|perl|ruby|node)\b` +
		`|\bbase64\s+(-d|-D|--decode)\b[^\n|]*\|\s*(sh|bash|zsh|python3?)\b` +
		`|/dev/tcp/[0-9A-Za-z.-]+/\d+` +
		`|\b(iex|Invoke-Expression)\b[^\n]*\b(iwr|irm|Invoke-WebRequest|DownloadString)\b`)
	// characters a reader does not see and a model does: zero-width, direction overrides, tag characters
	hiddenText = regexp.MustCompile(`[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{2066}-\x{2069}\x{E0000}-\x{E007F}]{2,}|[\x{202A}-\x{202E}\x{E0000}-\x{E007F}]`)
)

const skillFileCap = 256 << 10

// skills lists each harness's skills and plugins, and reads a skill's instructions and the scripts beside them.
func (h *hostReader) skills() {
	for _, path := range h.glob(h.inHomes(".claude/plugins/installed_plugins.json")...) {
		var installed struct {
			Plugins map[string][]struct{ Version string }
		}
		raw, err := readCapped(path, maxConfigFile)
		if err != nil || json.Unmarshal(raw, &installed) != nil {
			continue
		}
		names := make([]string, 0, len(installed.Plugins))
		for n := range installed.Plugins {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			for _, p := range installed.Plugins[n] {
				h.inv.AgentSurface = append(h.inv.AgentSurface, HostAgentItem{Kind: "plugin", Name: n, Version: p.Version, Where: h.label(filepath.Dir(path))})
			}
		}
	}
	for _, path := range h.glob(h.inHomes(".codex/config.toml", ".codex-*/config.toml")...) {
		raw, err := readCapped(path, maxConfigFile)
		if err != nil {
			continue
		}
		for _, m := range codexPlugin.FindAllStringSubmatch(string(raw), -1) {
			h.inv.AgentSurface = append(h.inv.AgentSurface, HostAgentItem{Kind: "plugin", Name: m[1], Where: h.label(path)})
		}
	}
	seen := map[string]bool{}
	for _, hn := range harnesses(h.goos) {
		for _, file := range h.glob(h.inHomes(hn.skills...)...) {
			dir := filepath.Dir(file)
			if seen[dir] {
				continue
			}
			seen[dir] = true
			name, where := filepath.Base(dir), h.label(filepath.Dir(dir))
			h.inv.AgentSurface = append(h.inv.AgentSurface, HostAgentItem{Kind: "skill", Name: name, Where: where})
			h.scan(dir, "skill", name, where)
		}
		// a file the harness loads as a plugin runs inside it, with everything the harness can do
		for _, path := range h.glob(h.inHomes(hn.scripts...)...) {
			name, where := filepath.Base(path), h.label(filepath.Dir(path))
			h.inv.AgentSurface = append(h.inv.AgentSurface, HostAgentItem{Kind: "plugin", Name: name, Where: where, Detail: "a local file " + hn.name + " loads"})
			h.scan(path, "plugin", name, where)
		}
	}
}

var codexPlugin = regexp.MustCompile(`(?m)^\[plugins\."([^"]+)"\]`)

// scan reads the files under a path (a skill's directory, a plugin file) for a download handed to a shell and,
// in its Markdown, for characters a reader does not see.
func (h *hostReader) scan(root, kind, name, where string) {
	found := map[string]string{}
	walkErr := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > skillFileCap {
			return nil
		}
		raw, err := readCapped(p, maxConfigFile)
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == "." {
			rel = d.Name()
		}
		if m := pipeToShell.Find(raw); m != nil && found["pipe_to_shell"] == "" {
			found["pipe_to_shell"] = rel + ": " + clip(string(m))
		}
		if strings.HasSuffix(p, ".md") && hiddenText.Match(raw) && found["hidden_text"] == "" {
			found["hidden_text"] = rel + " has characters a reader does not see and the agent does"
		}
		return nil
	})
	if walkErr != nil {
		return
	}
	for _, risk := range []string{"pipe_to_shell", "hidden_text"} {
		if found[risk] != "" {
			h.risk(HostRisk{risk, kind, name, where, found[risk]})
		}
	}
}

func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

// hooks lists the commands a harness runs by itself on its own events, from the user's settings and each plugin.
// An event's entry is a command, or a group of them under `hooks`.
func (h *hostReader) hooks() {
	type command struct {
		Command string
		Hooks   []struct{ Command string }
	}
	var files []string
	for _, hn := range harnesses(h.goos) {
		files = append(files, h.inHomes(hn.hooks...)...)
	}
	seen := map[string]bool{}
	for _, path := range h.glob(files...) {
		if seen[path] {
			continue
		}
		seen[path] = true
		var f struct{ Hooks map[string][]command }
		raw, err := readCapped(path, maxConfigFile)
		if err != nil || json.Unmarshal(stripJSONComments(raw), &f) != nil {
			continue
		}
		events := make([]string, 0, len(f.Hooks))
		for e := range f.Hooks {
			events = append(events, e)
		}
		sort.Strings(events)
		where := h.label(path)
		for _, event := range events {
			for _, entry := range f.Hooks[event] {
				commands := []string{entry.Command}
				for _, hook := range entry.Hooks {
					commands = append(commands, hook.Command)
				}
				for _, c := range commands {
					if strings.TrimSpace(c) == "" {
						continue
					}
					name := filepath.Base(strings.Fields(c)[0])
					h.inv.AgentSurface = append(h.inv.AgentSurface, HostAgentItem{Kind: "hook", Name: name, Where: where, Detail: "on " + event})
					if m := pipeToShell.FindString(c); m != "" {
						h.risk(HostRisk{"pipe_to_shell", "hook", name, where, "on " + event + ": " + clip(m)})
					}
				}
			}
		}
	}
}

var (
	codexNever  = regexp.MustCompile(`(?m)^approval_policy\s*=\s*"never"`)
	codexDanger = regexp.MustCompile(`(?m)^sandbox_mode\s*=\s*"danger-full-access"`)
)

// approvals reports an agent set to run commands without asking, by default, for every session.
func (h *hostReader) approvals() {
	for _, path := range h.glob(h.inHomes(".claude/settings.json", ".claude/settings.local.json")...) {
		var s struct {
			Permissions struct{ DefaultMode string }
		}
		raw, err := readCapped(path, maxConfigFile)
		if err == nil && json.Unmarshal(stripJSONComments(raw), &s) == nil && s.Permissions.DefaultMode == "bypassPermissions" {
			h.risk(HostRisk{"approvals_off", "agent", "Claude Code", h.label(path), "permissions.defaultMode is bypassPermissions: every session runs tools without asking"})
		}
	}
	for _, path := range h.glob(h.inHomes(".codex/config.toml")...) {
		raw, err := readCapped(path, maxConfigFile)
		if err == nil && codexNever.Match(raw) && codexDanger.Match(raw) {
			h.risk(HostRisk{"approvals_off", "agent", "Codex", h.label(path), "approval_policy is never with sandbox_mode danger-full-access: commands run unasked and unconfined"})
		}
	}
}

// extensionSource is the HostSource name of the editor extensions checked against the marketplaces' removals.
const extensionSource = "editor extensions"

// AddExtensions takes the answer for inv.Extensions into the scan: the entries join Entries under their own
// source, the items join res, and an extension a marketplace removed becomes a risk naming where and why. With
// checked false (an API that does not judge extensions) they are counted as read and not checked instead.
func (inv *HostInventory) AddExtensions(res *StackResult, ext StackResult, checked bool) {
	if len(inv.Extensions) == 0 {
		return
	}
	src := HostSource{Name: extensionSource, Detail: count(len(inv.Extensions), "extension", "extensions")}
	if !checked {
		for _, e := range inv.Extensions {
			name, version := extensionName(e)
			inv.NotAssessed = append(inv.NotAssessed, HostComponent{Name: name, Version: version, Source: extensionSource,
				Reason: "this SecurityContext API cannot check editor extensions (it has no marketplace removal lists)"})
			delete(inv.FoundIn, e)
		}
		src.NotAssessed = len(inv.Extensions)
		inv.Sources = append(inv.Sources, src)
		return
	}
	for _, e := range inv.Extensions {
		inv.Entries = append(inv.Entries, e)
		inv.EntrySource[e] = extensionSource
	}
	src.Sent = len(inv.Extensions)
	inv.Sources = append(inv.Sources, src)
	for _, it := range ext.Items {
		if len(it.Removed) == 0 {
			continue
		}
		name, _ := extensionName(it.Input)
		where := strings.Join(inv.FoundIn[it.Input], ", ")
		risk := "removed"
		if it.Malicious {
			risk = "removed_malware"
		}
		inv.Risks = append(inv.Risks, HostRisk{risk, "extension", name, where, it.Note})
	}
	mergeStack(res, ext)
}

// extensionName is an extension entry's publisher.name and version.
func extensionName(entry string) (name, version string) {
	body := strings.TrimPrefix(entry, "pkg:vscode-extension/")
	body, version, _ = strings.Cut(body, "@")
	if u, err := url.PathUnescape(strings.Replace(body, "/", ".", 1)); err == nil {
		body = u
	}
	return strings.ToLower(body), version
}
