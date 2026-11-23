package vulnx

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const plist = `<?xml version="1.0"?><plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>%ID%</string>
<key>CFBundleShortVersionString</key><string>%V%</string></dict></plist>`

func writePlist(t *testing.T, root, app, id, version string) {
	t.Helper()
	body := strings.NewReplacer("%ID%", id, "%V%", version).Replace(plist)
	writeFile(t, root, "Applications/"+app+".app/Contents/Info.plist", body)
}

func TestHostAITools(t *testing.T) {
	skipOnWindows(t)
	root := t.TempDir()
	writePlist(t, root, "Cursor", "com.todesktop.230313mzl4w4u92", "1.2.3")
	writePlist(t, root, "LM Studio", "ai.elementlabs.lmstudio", "0.3.1")
	writePlist(t, root, "Notes", "com.example.notes", "1.0")
	writeFile(t, root, "Users/a/.local/share/claude/versions/2.1.9/claude", "x")
	writeFile(t, root, "Users/a/.local/share/claude/versions/2.1.10/claude", "x")
	writeFile(t, root, "Users/a/.lmstudio/bin/lms", "x")
	if err := os.Chmod(filepath.Join(root, "Users/a/.lmstudio/bin/lms"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "Users/b/.lmstudio/bin/lms", "not executable")
	ext := "Users/a/.vscode/extensions/"
	writeFile(t, root, ext+"saoudrizwan.claude-dev-3.0.1/package.json", `{"publisher":"saoudrizwan","name":"claude-dev","version":"3.0.1","displayName":"Cline"}`)
	writeFile(t, root, ext+"github.copilot-1.250.0/package.json", `{"publisher":"GitHub","name":"copilot","version":"1.250.0","displayName":"GitHub Copilot"}`)
	writeFile(t, root, ext+"github.copilot-chat-0.30.0/package.json", `{"publisher":"GitHub","name":"copilot-chat","version":"0.30.0"}`)
	writeFile(t, root, ext+"acme.helper-1.0.0/package.json", `{"publisher":"acme","name":"helper","version":"1.0.0","displayName":"Acme AI Helper"}`)
	writeFile(t, root, ext+"ms-python.python-2024.1.0/package.json", `{"publisher":"ms-python","name":"python","version":"2024.1.0","displayName":"Python"}`)
	writeFile(t, root, ext+".obsolete", `{"github.copilot-chat-0.30.0":true}`)
	writeFile(t, root, "Users/a/.claude.json", `{
	  // the user's servers
	  "mcpServers": {
	    "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/tmp"], "env": {"TOKEN": "secret"}},
	    "loose": {"command": "npx", "args": ["-y", "mcp-remote"]},
	    "cached": {"command": "npx", "args": ["some-server@latest"]},
	    "local": {"command": "/usr/local/bin/thing", "args": ["serve"]},
	    "remote": {"type": "http", "url": "https://mcp.example.com"},
	  },
	  "projects": {"/p": {"mcpServers": {"py": {"command": "uvx", "args": ["--from", "Mcp_Server.git==0.6.2", "mcp-server-git"]}}}}
	}`)
	writeFile(t, root, "Users/a/.npm/_npx/abc/node_modules/some-server/package.json", `{"version":"1.4.0"}`)
	writeFile(t, root, "Users/a/.cursor/mcp.json", `{"mcpServers": {"local": {"command": "/usr/local/bin/thing"}}}`)
	writeFile(t, root, "Users/a/.codex/config.toml", "model = \"x\"\n[mcp_servers.docs]\ncommand = \"npx\"\nargs = [\"-y\", \"docs-server@0.2.0\"]\n\n[mcp_servers.docs.env]\ncommand = \"ignored\"\n[mcp_servers.web]\nurl = \"https://x.example\"\n")

	h := newHostReader(root, "darwin")
	h.applications()
	h.aiTools()

	var got []string
	for _, e := range h.inv.Entries {
		if h.inv.EntrySource[e] == aiSource {
			got = append(got, e)
		}
	}
	slices.Sort(got)
	want := []string{
		"cpe:2.3:a:anthropic:claude_code:2.1.10:*:*:*:*:*:*:*",
		"cpe:2.3:a:anysphere:cursor:1.2.3:*:*:*:*:*:*:*",
		"cpe:2.3:a:cline:cline:3.0.1:*:*:*:*:*:*:*",
		"pkg:npm/%40modelcontextprotocol/server-filesystem@2025.8.21",
		"pkg:npm/docs-server@0.2.0",
		"pkg:npm/some-server@1.4.0",
		"pkg:pypi/mcp-server-git@0.6.2",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("entries:\n got %q\nwant %q", got, want)
	}
	if in := h.inv.FoundIn["pkg:npm/docs-server@0.2.0"]; !reflect.DeepEqual(in, []string{"~a/.codex/config.toml"}) {
		t.Fatalf("found in %q", in)
	}
	notChecked := map[string]string{}
	for _, c := range h.inv.NotAssessed {
		notChecked[c.Source+": "+c.Name] = c.Version
	}
	wantNot := map[string]string{
		"ai tools: LM Studio": "0.3.1", "ai tools: lms (LM Studio CLI)": "", "ai tools: github.copilot": "1.250.0", "ai tools: acme.helper": "1.0.0",
		"ai tools: MCP server loose": "mcp-remote", "ai tools: MCP server local": "",
		"applications: Notes": "1.0",
	}
	if !reflect.DeepEqual(notChecked, wantNot) {
		t.Fatalf("not checked:\n got %q\nwant %q", notChecked, wantNot)
	}
	src := h.inv.Sources[len(h.inv.Sources)-1]
	if src.Name != aiSource || src.Sent != 7 || src.NotAssessed != 6 ||
		src.Detail != "2 applications, 2 agent CLIs, 3 editor extensions, 9 configured MCP servers" {
		t.Fatalf("source %+v", src)
	}
}

func TestRunnerPackage(t *testing.T) {
	for _, c := range []struct {
		command  []string
		eco      string
		name, at string
	}{
		{[]string{"npx", "-y", "@scope/server@1.2.0", "--port", "1"}, "npm", "@scope/server", "1.2.0"},
		{[]string{"/opt/homebrew/bin/npx", "--package", "pkg@2.0.0", "run-it"}, "npm", "pkg", "2.0.0"},
		{[]string{"npx", "server@latest"}, "npm", "server", ""},
		{[]string{"npx", "server@^1.2.0"}, "npm", "server", ""},
		{[]string{"pnpm", "dlx", "server@3.1.4"}, "npm", "server", "3.1.4"},
		{[]string{"pnpm", "run", "server"}, "", "", ""},
		{[]string{"bun", "x", "server@0.1.0"}, "npm", "server", "0.1.0"},
		{[]string{"uvx", "--python", "3.12", "mcp-server-fetch==2025.1.17"}, "pypi", "mcp-server-fetch", "2025.1.17"},
		{[]string{"uvx", "mcp-server-fetch@0.6.3"}, "pypi", "mcp-server-fetch", "0.6.3"},
		{[]string{"uvx", "tool[extra]>=1.0"}, "pypi", "tool", ""},
		{[]string{"uv", "tool", "run", "--from", "pkg==1.0.1", "cmd"}, "pypi", "pkg", "1.0.1"},
		{[]string{"uv", "run", "server.py"}, "", "", ""},
		{[]string{"pipx", "run", "--spec", "pkg==4.0.0", "cmd"}, "pypi", "pkg", "4.0.0"},
		{[]string{"npx", "./local-server"}, "", "", ""},
		{[]string{"npx", "github:owner/repo"}, "", "", ""},
		{[]string{"uvx", "--from", "git+https://example.com/x.git", "x"}, "", "", ""},
		{[]string{"node", "server.js"}, "", "", ""},
		{[]string{"docker", "run", "-i", "image:1.0"}, "", "", ""},
	} {
		eco, spec := runnerPackage(c.command)
		name, at := "", ""
		if eco != "" {
			name, at = splitSpec(eco, spec)
		}
		if eco != c.eco || name != c.name || at != c.at {
			t.Errorf("%q: got %q %q %q, want %q %q %q", c.command, eco, name, at, c.eco, c.name, c.at)
		}
	}
}

func TestNewestVersion(t *testing.T) {
	root := t.TempDir()
	for _, v := range []string{"2.1.9", "2.1.10", "2.0.99", "tmp", "2.1.10.partial"} {
		writeFile(t, root, v+"/x", "")
	}
	if got := newestVersion(root); got != "2.1.10" {
		t.Fatalf("got %q", got)
	}
}

func TestStripJSONComments(t *testing.T) {
	got := string(stripJSONComments([]byte("{\"a\": \"x // y, }\", /* c */ \"b\": [1, 2,], // end\n}")))
	if want := "{\"a\": \"x // y, }\",   \"b\": [1, 2] \n}"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
