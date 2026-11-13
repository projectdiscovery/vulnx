package vulnx

import (
	"cmp"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// harness is a coding agent or an editor that runs one: where, under a home, it keeps what it loads and runs. A
// path that is not there reads nothing, so a harness that is not installed costs a failed stat.
type harness struct {
	name    string
	mcp     []string // JSON (comments allowed) or YAML files that configure MCP servers
	mcpTOML []string // TOML files whose [mcp_servers.<name>] tables do
	skills  []string // globs of SKILL.md
	hooks   []string // JSON files of commands run on the harness's own events
	plugins []string // JSON files listing packages the harness loads into itself (OpenCode's `plugin`)
	scripts []string // globs of local plugin files the harness loads
}

// editorStorage is where an editor of the VS Code family keeps its extensions' own settings.
func editorStorage(goos, extension, file string) []string {
	var out []string
	for _, editor := range []string{"Code", "Code - Insiders", "Cursor", "Windsurf", "VSCodium"} {
		base := ".config/" + editor
		if goos == "darwin" {
			base = "Library/Application Support/" + editor
		}
		out = append(out, base+"/User/globalStorage/"+extension+"/settings/"+file)
	}
	return out
}

func harnesses(goos string) []harness {
	support := func(mac, linux string) string {
		if goos == "darwin" {
			return "Library/Application Support/" + mac
		}
		return ".config/" + linux
	}
	return []harness{
		{name: "Claude Code",
			mcp:    []string{".claude.json", ".claude/settings.json"},
			skills: []string{".claude/skills/*/SKILL.md", ".claude/plugins/cache/*/*/*/skills/*/SKILL.md"},
			hooks:  []string{".claude/settings.json", ".claude/settings.local.json", ".claude/plugins/cache/*/*/*/hooks/hooks.json"}},
		{name: "Claude Desktop", mcp: []string{support("Claude/claude_desktop_config.json", "Claude/claude_desktop_config.json")}},
		{name: "Codex",
			mcpTOML: []string{".codex/config.toml", ".codex-*/config.toml"},
			skills:  []string{".codex/skills/*/SKILL.md", ".codex/plugins/cache/*/*/*/skills/*/SKILL.md"},
			hooks:   []string{".codex/hooks.json", ".codex-*/hooks.json"}},
		{name: "Cursor",
			mcp:    []string{".cursor/mcp.json"},
			skills: []string{".cursor/skills/*/SKILL.md", ".cursor/skills-cursor/*/SKILL.md", ".cursor/plugins/cache/*/*/*/skills/*/SKILL.md", ".cursor/plugins/local/*/skills/*/SKILL.md"},
			hooks:  []string{".cursor/hooks.json"}},
		{name: "VS Code", mcp: []string{support("Code/User/mcp.json", "Code/User/mcp.json")}},
		{name: "Windsurf", mcp: []string{".codeium/windsurf/mcp_config.json"}, skills: []string{".codeium/windsurf/skills/*/SKILL.md"}},
		{name: "Gemini CLI",
			mcp:    []string{".gemini/settings.json", ".gemini/extensions/*/gemini-extension.json"},
			skills: []string{".gemini/skills/*/SKILL.md", ".gemini/extensions/*/skills/*/SKILL.md"},
			hooks:  []string{".gemini/settings.json"}},
		{name: "Qwen Code", mcp: []string{".qwen/settings.json"}, skills: []string{".qwen/skills/*/SKILL.md"}},
		{name: "OpenCode",
			mcp:     []string{".config/opencode/opencode.json", ".config/opencode/opencode.jsonc", ".opencode.json"},
			skills:  []string{".config/opencode/skill/*/SKILL.md", ".config/opencode/skills/*/SKILL.md"},
			plugins: []string{".config/opencode/opencode.json", ".config/opencode/opencode.jsonc"},
			scripts: []string{".config/opencode/plugin/*", ".config/opencode/plugins/*"}},
		{name: "Copilot CLI", mcp: []string{".copilot/mcp-config.json"}, skills: []string{".copilot/skills/*/SKILL.md"}},
		{name: "Goose", mcp: []string{".config/goose/config.yaml"}, skills: []string{".config/goose/skills/*/SKILL.md"}},
		{name: "Amp", mcp: []string{".config/amp/settings.json"}, skills: []string{".config/amp/skills/*/SKILL.md"}},
		{name: "Droid", mcp: []string{".factory/mcp.json"}, skills: []string{".factory/skills/*/SKILL.md"}},
		{name: "Kiro", mcp: []string{".kiro/settings/mcp.json"}, skills: []string{".kiro/skills/*/SKILL.md"}},
		{name: "Amazon Q", mcp: []string{".aws/amazonq/mcp.json"}},
		{name: "Zed", mcp: []string{".config/zed/settings.json"}},
		{name: "Crush", mcp: []string{".config/crush/crush.json"}},
		{name: "Junie", mcp: []string{".junie/mcp/mcp.json"}},
		{name: "LM Studio", mcp: []string{".lmstudio/mcp.json"}},
		{name: "Continue", mcp: []string{".continue/config.yaml", ".continue/config.json"}},
		{name: "Cline", mcp: editorStorage(goos, "saoudrizwan.claude-dev", "cline_mcp_settings.json")},
		{name: "Roo Code", mcp: editorStorage(goos, "rooveterinaryinc.roo-cline", "mcp_settings.json")},
		{name: "Kilo Code", mcp: editorStorage(goos, "kilocode.kilo-code", "mcp_settings.json")},
		// skills several agents read from one place
		{name: "shared", skills: []string{".agents/skills/*/SKILL.md", ".config/agents/skills/*/SKILL.md"}},
	}
}

// launch is how a configuration starts an MCP server: a command line, or a URL for one reached over the network.
type launch struct {
	name    string
	command []string
	url     string
}

// serverGroups are the keys under which the harnesses keep their MCP servers.
var serverGroups = []string{"mcpServers", "mcp_servers", "servers", "mcp", "amp.mcpServers", "context_servers", "extensions"}

// launches reads the MCP servers of one JSON or YAML configuration, in name order. A group is an object keyed by
// server name, or a list of servers each with a `name`. Only how a server is started is read: its environment and
// headers, where credentials are, never are.
func launches(path string, raw []byte) []launch {
	var cfg map[string]any
	if ext := strings.ToLower(filepath.Ext(path)); ext == ".yaml" || ext == ".yml" {
		if yaml.Unmarshal(raw, &cfg) != nil {
			return nil
		}
	} else if json.Unmarshal(stripJSONComments(raw), &cfg) != nil {
		return nil
	}
	var out []launch
	group := func(v any) {
		switch g := v.(type) {
		case map[string]any:
			names := make([]string, 0, len(g))
			for n := range g {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				if s, ok := g[n].(map[string]any); ok {
					if l, ok := serverLaunch(n, s); ok {
						out = append(out, l)
					}
				}
			}
		case []any:
			for _, item := range g {
				if s, ok := item.(map[string]any); ok {
					name, _ := s["name"].(string)
					if l, ok := serverLaunch(name, s); ok && name != "" {
						out = append(out, l)
					}
				}
			}
		}
	}
	for _, key := range serverGroups {
		group(cfg[key])
	}
	if projects, ok := cfg["projects"].(map[string]any); ok { // one agent keeps each project's servers under it
		keys := make([]string, 0, len(projects))
		for k := range projects {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if p, ok := projects[k].(map[string]any); ok {
				group(p["mcpServers"])
			}
		}
	}
	return out
}

// serverLaunch reads one server: its URL under any of the names the harnesses use, or its command, which is a
// string with `args`, a list, or an object {path, args}.
func serverLaunch(name string, s map[string]any) (launch, bool) {
	l := launch{name: name}
	for _, key := range []string{"url", "httpUrl", "serverUrl", "uri"} {
		if u, ok := s[key].(string); ok && u != "" {
			l.url = u
			return l, true
		}
	}
	args := stringList(s["args"])
	switch c := cmp.Or(s["command"], s["cmd"]).(type) {
	case string:
		l.command = append([]string{c}, args...)
	case []any:
		l.command = stringList(c)
	case map[string]any:
		if p, ok := c["path"].(string); ok && p != "" {
			l.command = append([]string{p}, stringList(c["args"])...)
		}
	}
	return l, len(l.command) > 0 && l.command[0] != ""
}

func stringList(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// mcpServers reads the MCP servers configured for the harnesses on the machine, each once per configuration.
func (h *hostReader) mcpServers() (out []mcpServer) {
	seen := map[string]bool{}
	read := func(path string, servers []launch) {
		label := h.label(path)
		for _, s := range servers {
			key := label + "\x00" + s.name
			if seen[key] {
				continue
			}
			seen[key] = true
			if s.url != "" {
				out = append(out, mcpServer{name: s.name, config: label, url: s.url})
				continue
			}
			m := mcpServer{name: s.name, config: label, command: s.command}
			m.spec, m.purl, m.reason = h.runnerEntry(filepath.Dir(path), s.command)
			out = append(out, m)
		}
	}
	for _, hn := range harnesses(h.goos) {
		for _, path := range h.glob(h.inHomes(hn.mcp...)...) {
			if raw, err := os.ReadFile(path); err == nil {
				read(path, launches(path, raw))
			}
		}
		for _, path := range h.glob(h.inHomes(hn.mcpTOML...)...) {
			raw, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var servers []launch
			for _, s := range tomlMCPServers(string(raw)) {
				servers = append(servers, launch(s))
			}
			read(path, servers)
		}
	}
	return out
}

// runnerEntry is what a command line that runs a package resolves to: the package specifier, its purl when a
// version is known (pinned, or the one copy in the runner's cache), else why there is none.
func (h *hostReader) runnerEntry(from string, command []string) (spec, purl, reason string) {
	eco, spec := runnerPackage(command)
	if eco == "" {
		return "", "", "a program on this machine, not a package"
	}
	return h.packageEntry(from, eco, spec)
}

func (h *hostReader) packageEntry(from, eco, spec string) (string, string, string) {
	name, version := splitSpec(eco, spec)
	if version == "" && eco == "npm" {
		version = h.npxCached(from, name)
	}
	switch {
	case version == "":
		return name, "", "no version pinned: whichever is newest when it starts"
	case eco == "npm":
		return spec, npmPurl(name, version), ""
	}
	return spec, "pkg:pypi/" + pypiNameSep.ReplaceAllString(strings.ToLower(name), "-") + "@" + version, ""
}

// loadedPackage is a package a harness loads into itself by name (OpenCode's `plugin` list).
type loadedPackage struct{ harness, config, spec, purl, reason string }

func (h *hostReader) loadedPackages() (out []loadedPackage) {
	for _, hn := range harnesses(h.goos) {
		for _, path := range h.glob(h.inHomes(hn.plugins...)...) {
			raw, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var cfg struct {
				Plugin []string `json:"plugin"`
			}
			if json.Unmarshal(stripJSONComments(raw), &cfg) != nil {
				continue
			}
			for _, spec := range cfg.Plugin {
				if spec == "" || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.Contains(spec, ":") {
					continue // a local file or a URL: read with the harness's local plugin files
				}
				p := loadedPackage{harness: hn.name, config: h.label(path)}
				p.spec, p.purl, p.reason = h.packageEntry(filepath.Dir(path), "npm", spec)
				out = append(out, p)
			}
		}
	}
	return out
}
