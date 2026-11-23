package vulnx

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// modelSource is the HostSource name of what localModels reads.
const modelSource = "local models"

// localModels reads what running open-weight models on the machine brings: the model files in the stores the
// runtimes keep (a model in a pickle format runs code when it is loaded; one that ships its own Python runs that),
// the engines a model app bundles, and whether a runtime with no login is set to listen beyond this machine.
// The runtimes themselves are read by the other sources: a Go or Rust binary, a formula, a Python package.
func (h *hostReader) localModels() {
	var notAssessed []HostComponent
	var parts []string

	engines := 0
	for _, dir := range h.glob(h.inHomes(".lmstudio/extensions/backends/*")...) {
		var manifest struct{ Version, Engine string }
		raw, err := readCapped(filepath.Join(dir, "backend-manifest.json"), maxConfigFile)
		if err != nil || json.Unmarshal(raw, &manifest) != nil || manifest.Engine == "" || manifest.Version == "" {
			continue
		}
		engines++
		// the version is the app's own numbering of its build of the engine, not the engine's: nothing exact to check
		notAssessed = append(notAssessed, HostComponent{Name: "LM Studio " + manifest.Engine + " engine", Version: manifest.Version,
			Reason: "the app's own build of the engine, numbered by the app"})
		h.inv.AgentSurface = append(h.inv.AgentSurface, HostAgentItem{Kind: "runtime", Name: "LM Studio " + manifest.Engine + " engine",
			Version: manifest.Version, Where: h.label(filepath.Dir(dir))})
	}
	if engines > 0 {
		parts = append(parts, count(engines, "bundled engine", "bundled engines"))
	}

	models := 0
	for _, m := range h.modelStores() {
		models++
		h.inv.AgentSurface = append(h.inv.AgentSurface, HostAgentItem{Kind: "model", Name: m.name, Where: m.where, Detail: strings.Join(m.formats, ", ")})
		if m.dir == "" {
			continue
		}
		f := modelFindings(m.dir)
		switch {
		case f.imports != "":
			h.risk(HostRisk{"model_runs_commands", "model", m.name, m.where, f.imports})
		case f.pickle != "":
			h.risk(HostRisk{"pickle_format", "model", m.name, m.where, f.pickle})
		}
		if f.code != "" {
			h.risk(HostRisk{"custom_code", "model", m.name, m.where, f.code})
		}
	}
	if models > 0 {
		parts = append(parts, count(models, "model", "models"))
	}
	h.exposedRuntimes()
	if len(parts) > 0 {
		h.add(modelSource, strings.Join(parts, ", "), nil, notAssessed)
	}
}

type localModel struct {
	name, where string
	dir         string   // where its files are, when they are files to read
	formats     []string // gguf, for a store that holds only that
}

// modelStores lists the models in the stores the runtimes keep under each home.
func (h *hostReader) modelStores() []localModel {
	var out []localModel
	for _, dir := range h.glob(h.inHomes(".cache/huggingface/hub/models--*")...) {
		name := strings.Replace(strings.TrimPrefix(filepath.Base(dir), "models--"), "--", "/", 1)
		out = append(out, localModel{name: name, where: h.label(filepath.Dir(dir)), dir: filepath.Join(dir, "snapshots")})
	}
	for _, dir := range h.glob(h.inHomes(".lmstudio/models/*/*", ".cache/lm-studio/models/*/*")...) {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			out = append(out, localModel{name: filepath.Base(filepath.Dir(dir)) + "/" + filepath.Base(dir), where: h.label(filepath.Dir(filepath.Dir(dir))), dir: dir})
		}
	}
	for _, file := range h.glob(h.inHomes(".cache/torch/hub/checkpoints/*")...) {
		out = append(out, localModel{name: filepath.Base(file), where: h.label(filepath.Dir(file)), dir: file})
	}
	// a store of GGUF blobs under content hashes: named by its manifests, nothing in it runs
	for _, tag := range h.glob(h.inHomes(".ollama/models/manifests/*/*/*/*", ".ollama/models/manifests-v2/*/*/*/*")...) {
		model := filepath.Dir(tag)
		name := filepath.Base(model) + ":" + filepath.Base(tag)
		if ns := filepath.Base(filepath.Dir(model)); ns != "library" {
			name = ns + "/" + name
		}
		out = append(out, localModel{name: name, where: h.label(strings.SplitAfter(tag, "/.ollama/models")[0]), formats: []string{"gguf"}})
	}
	return out
}

type modelFinding struct {
	imports string // a pickle that imports something that runs commands
	pickle  string // a file in a pickle format
	code    string // Python the model loads as its own code
}

var pickleExt = map[string]bool{".pt": true, ".pth": true, ".bin": true, ".pkl": true, ".pickle": true, ".ckpt": true, ".joblib": true}

const modelFilesCap = 5000

// modelFindings reads a model's files: which are pickles and what those import, and whether the model ships
// Python its configuration names as its own classes (auto_map: run when loaded with remote code trusted).
func modelFindings(root string) modelFinding {
	var f modelFinding
	var pickles, python []string
	automap := false
	seen := 0
	walkErr := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if seen++; seen > modelFilesCap {
			return filepath.SkipAll
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == "." {
			rel = d.Name()
		}
		rel = filepath.ToSlash(rel) // a report names paths with / on every system
		if i := strings.Index(rel, "/"); i > 0 && strings.Contains(filepath.ToSlash(root), "/snapshots") {
			rel = rel[i+1:] // a snapshot's revision is not part of the file's name
		}
		switch ext := strings.ToLower(filepath.Ext(p)); {
		case pickleExt[ext]:
			isPickle, imports := pickleImports(p)
			if imports != "" && f.imports == "" {
				f.imports = rel + " imports " + imports + " when loaded"
			}
			if isPickle {
				pickles = append(pickles, rel)
			}
		case ext == ".py":
			python = append(python, rel)
		case d.Name() == "config.json":
			if raw, err := readCapped(p, maxConfigFile); err == nil && bytes.Contains(raw, []byte(`"auto_map"`)) {
				automap = true
			}
		}
		return nil
	})
	if walkErr != nil {
		return f
	}
	if len(pickles) > 0 {
		sort.Strings(pickles)
		f.pickle = listed(pickles) + ": a pickle, which can run code when loaded; safetensors and GGUF cannot"
	}
	if automap && len(python) > 0 {
		sort.Strings(python)
		f.code = listed(python) + ": the model's own code, run when it is loaded with remote code trusted"
	}
	return f
}

func listed(names []string) string {
	if len(names) > 3 {
		return strings.Join(names[:3], ", ") + " and " + count(len(names)-3, "more", "more")
	}
	return strings.Join(names, ", ")
}

// commandModules are the modules a model's pickle has no reason to import and an attacker's does: each runs
// a command, evaluates code or opens a connection. A second-stage name is read only for builtins, where most are
// harmless.
var (
	commandModules = `os|posix|nt|subprocess|runpy|socket|pty|commands|webbrowser|importlib|pip|ctypes|code|timeit|shutil|requests|urllib\.request|http\.client|asyncio\.subprocess|multiprocessing\.util`
	builtinNames   = `eval|exec|compile|__import__|getattr|open|breakpoint`
	pickleGlobal   = regexp.MustCompile(`c((?:` + commandModules + `)\n[\w.]+|(?:builtins|__builtin__)\n(?:` + builtinNames + `))\n`)
	commandModule  = regexp.MustCompile(`^(?:` + commandModules + `)$`)
	builtinName    = regexp.MustCompile(`^(?:` + builtinNames + `)$`)
)

// A pickle is read up to pickleReadCap bytes, an archive's pickles together; an archive is read up to
// pickleEntriesCap pickles (PyTorch's holds one).
const (
	pickleReadCap    = 8 << 20
	pickleEntriesCap = 16
)

// pickleImports reports whether a file is a pickle (a raw one, or the archive PyTorch saves, whose data.pkl is one)
// and, when its pickle imports something that runs commands, what ("os.system").
func pickleImports(path string) (isPickle bool, imports string) {
	file, err := openRegular(path)
	if err != nil {
		return false, ""
	}
	isPickle, data := pickleData(file)
	if file.Close() != nil || !isPickle {
		return false, ""
	}
	if m := pickleGlobal.FindSubmatch(data); m != nil {
		return true, strings.ReplaceAll(string(m[1]), "\n", ".")
	}
	return true, stackGlobal(data)
}

// pickleData is a file's pickle bytes, when it is a pickle or an archive of them.
func pickleData(file *os.File) (bool, []byte) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(file, head); err != nil {
		return false, nil
	}
	switch {
	case head[0] == 0x80 && head[1] >= 2 && head[1] <= 5:
		rest, err := io.ReadAll(io.LimitReader(file, pickleReadCap))
		if err != nil {
			return true, nil
		}
		return true, rest
	case head[0] != 'P' || head[1] != 'K':
		return false, nil
	}
	info, err := file.Stat()
	if err != nil {
		return false, nil
	}
	archive, err := zip.NewReader(file, info.Size())
	if err != nil {
		return false, nil
	}
	var data []byte
	isPickle, entries := false, 0
	for _, entry := range archive.File {
		if !strings.HasSuffix(entry.Name, ".pkl") {
			continue
		}
		isPickle = true
		if entries++; entries > pickleEntriesCap || len(data) >= pickleReadCap {
			break
		}
		r, err := entry.Open()
		if err != nil {
			continue
		}
		part, err := io.ReadAll(io.LimitReader(r, int64(pickleReadCap-len(data))))
		if closeErr := r.Close(); err == nil && closeErr == nil {
			data = append(data, part...)
		}
	}
	return isPickle, data
}

// stackGlobal finds the import newer pickles write as two short strings and STACK_GLOBAL (each string followed
// by a MEMOIZE or not), and returns it when it is of a command-running module.
func stackGlobal(data []byte) string {
	const shortString, memoize, stackGlobal = 0x8c, 0x94, 0x93
	short := func(i int) (string, int) { // the short string at i and where what follows it starts
		if i+1 >= len(data) || data[i] != shortString || i+2+int(data[i+1]) > len(data) {
			return "", -1
		}
		end := i + 2 + int(data[i+1])
		if end < len(data) && data[end] == memoize {
			return string(data[i+2 : end]), end + 1
		}
		return string(data[i+2 : end]), end
	}
	for i := bytes.IndexByte(data, shortString); i >= 0 && i < len(data); {
		module, next := short(i)
		if next > 0 {
			if name, after := short(next); after > 0 && after < len(data) && data[after] == stackGlobal {
				if commandModule.MatchString(module) || (module == "builtins" || module == "__builtin__") && builtinName.MatchString(name) {
					return module + "." + name
				}
			}
		}
		step := bytes.IndexByte(data[i+1:], shortString)
		if step < 0 {
			break
		}
		i += 1 + step
	}
	return ""
}

var (
	// an assignment (export OLLAMA_HOST=..., Environment="OLLAMA_HOST=...") or fish's and launchctl's
	// set/setenv OLLAMA_HOST ...; a test or a read of the variable ([ -z "$OLLAMA_HOST" ]) sets nothing
	ollamaHost = regexp.MustCompile(`(?:^|[\s;"'])OLLAMA_HOST=["']?([^\s"'<>;$]+)` +
		`|\b(?:set(?:\s+-[a-zA-Z]+)*|setenv)\s+OLLAMA_HOST\s+["']?([^\s"'<>;$]+)`)
	ollamaHostPlist = regexp.MustCompile(`<key>OLLAMA_HOST</key>\s*<string>([^<]+)</string>`)
)

// exposedRuntimes reports a model runtime with no login that its configuration sets to listen beyond this machine.
// It reads the configuration, not the sockets: what the runtime will do the next time it starts.
func (h *hostReader) exposedRuntimes() {
	files := h.inHomes(".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile", ".config/fish/config.fish",
		"Library/LaunchAgents/*ollama*.plist")
	files = append(files, "etc/systemd/system/ollama.service", "etc/systemd/system/ollama.service.d/*.conf", "etc/default/ollama",
		"usr/lib/systemd/system/ollama.service", "Library/LaunchDaemons/*ollama*.plist")
	for _, path := range h.glob(files...) {
		raw, err := readCapped(path, maxConfigFile)
		if err != nil {
			continue
		}
		var hosts []string
		if strings.HasSuffix(path, ".plist") { // the key and its value are on two lines
			for _, m := range ollamaHostPlist.FindAllSubmatch(raw, -1) {
				hosts = append(hosts, string(m[1]))
			}
		} else {
			for _, line := range bytes.Split(raw, []byte("\n")) {
				if bytes.HasPrefix(bytes.TrimSpace(line), []byte("#")) {
					continue
				}
				if m := ollamaHost.FindSubmatch(line); m != nil {
					hosts = append(hosts, string(m[1]))
				}
			}
		}
		for _, host := range hosts {
			if !loopback(host) {
				h.risk(HostRisk{"exposed", "runtime", "Ollama", h.label(path),
					"OLLAMA_HOST is " + host + ": Ollama has no login, so anyone who reaches the port can run, pull and delete models"})
			}
		}
	}
	for _, path := range h.glob(h.inHomes(".lmstudio/.internal/http-server.json")...) {
		var server struct{ Host string }
		raw, err := readCapped(path, maxConfigFile)
		if err == nil && json.Unmarshal(raw, &server) == nil && server.Host != "" && !loopback(server.Host) {
			h.risk(HostRisk{"exposed", "runtime", "LM Studio", h.label(path),
				"its server listens on " + server.Host + ": anyone on the network who reaches the port can use the loaded models"})
		}
	}
}

// loopback reports whether an address (a host, host:port or a URL) is this machine only: localhost, a
// *.localhost name, or a loopback IP, an IPv4-mapped one (::ffff:127.0.0.1) included.
func loopback(addr string) bool {
	addr = strings.TrimPrefix(strings.TrimPrefix(addr, "http://"), "https://")
	addr = strings.TrimSuffix(addr, "/")
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
