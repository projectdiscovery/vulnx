package vulnx

// A folder scan: the lockfiles, manifests and SBOMs under a directory, read here, with the packages installed in
// it (node_modules, site-packages, gem specifications) and the Go and Rust programs it holds. Only names and
// versions are checked; every path stays relative to the folder.

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// Bounds on a folder walk.
const (
	maxFolderEntries  = 200_000   // files and directories visited
	maxFolderDepth    = 32        // directories below the folder
	maxFolderBinaries = 4_000     // executables read for embedded module lists
	minBinarySize     = 256 << 10 // smaller executables are scripts, not Go or Rust programs
)

// FolderNotRead is what a folder scan never reads, the last of its NotRead.
const FolderNotRead = "OS packages, the runtime snapshot and AI tools configured outside the folder (vulnx scan --host reads those)"

// folderSkip are directories a folder walk does not enter: version control holds no installed package.
var folderSkip = map[string]bool{".git": true, ".hg": true, ".svn": true}

// folderMCP are the MCP configurations a project keeps in its own tree.
var folderMCP = []string{".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".gemini/settings.json", ".roo/mcp.json"}

// folderSBOM is whether a file name is a JSON SBOM's: bom.json, *.cdx.json, *.spdx.json, sbom*.json.
func folderSBOM(name string) bool {
	n := strings.ToLower(name)
	return n == "bom.json" || strings.HasSuffix(n, ".cdx.json") || strings.HasSuffix(n, ".cyclonedx.json") ||
		strings.HasSuffix(n, ".spdx.json") || strings.HasPrefix(n, "sbom") && strings.HasSuffix(n, ".json")
}

// folderWalk collects a folder's sources before they are added, so each source is one row however many
// directories fed it.
type folderWalk struct {
	h        *hostReader
	root     string
	visited  int
	binaries int
	order    []string           // source names, in the order first seen
	entries  map[string][]found // source -> entries, with where each was found
	skipped  map[string][]HostComponent
	details  map[string]int // source -> files or directories read
}

func (w *folderWalk) rel(path string) string {
	rel, err := filepath.Rel(w.root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

func (w *folderWalk) collect(source, in string, entries []string, skipped []HostComponent) {
	if _, ok := w.details[source]; !ok {
		w.order = append(w.order, source)
	}
	w.details[source]++
	w.entries[source] = append(w.entries[source], foundIn(in, entries)...)
	w.skipped[source] = append(w.skipped[source], skipped...)
}

func (w *folderWalk) notRead(rel string, err error) {
	w.h.inv.NotRead = append(w.h.inv.NotRead, fmt.Sprintf("%s: %v", rel, err))
}

// FolderEntries reads what a directory installs and holds: lockfiles and manifests (parsed here), JSON SBOMs, the
// packages installed under it, its Go and Rust executables and the MCP servers its own configuration starts. The
// walk stays inside the folder: symlinks are not followed and version control directories are not entered.
func FolderEntries(ctx context.Context, dir string) (HostInventory, error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return HostInventory{}, err
	}
	if st, err := os.Stat(root); err != nil {
		return HostInventory{}, err
	} else if !st.IsDir() {
		return HostInventory{}, fmt.Errorf("%s is not a directory", dir)
	}
	w := &folderWalk{h: newHostReader(root, runtime.GOOS), root: root, entries: map[string][]found{},
		skipped: map[string][]HostComponent{}, details: map[string]int{}}
	w.h.ctx = ctx
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			if path == root {
				return err
			}
			w.notRead(w.rel(path), err)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if w.visited++; w.visited > maxFolderEntries {
			w.h.inv.NotRead = append(w.h.inv.NotRead, fmt.Sprintf("everything after the first %d files and directories", maxFolderEntries))
			return fs.SkipAll
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // a link may lead out of the folder
		}
		rel := w.rel(path)
		if d.IsDir() {
			return w.dir(path, rel, d.Name())
		}
		if d.Type().IsRegular() {
			w.file(path, rel, d)
		}
		return nil
	})
	if err != nil {
		return w.h.inv, err
	}
	// what pins a version counts a package first: a lockfile or SBOM, then a project's MCP configuration, then
	// what is installed, then programs;
	rank := func(source string) int {
		switch {
		case source == "mcp servers":
			return 1
		case strings.HasPrefix(source, "installed "):
			return 2
		case strings.HasSuffix(source, " binaries"):
			return 3
		}
		return 0
	}
	// and among lockfiles the project's own before a nested copy (a worktree, an example)
	slices.SortStableFunc(w.order, func(a, b string) int {
		if d := rank(a) - rank(b); d != 0 {
			return d
		}
		return strings.Count(a, "/") - strings.Count(b, "/")
	})
	for _, source := range w.order {
		detail := count(w.details[source], "file", "files")
		if strings.HasPrefix(source, "installed ") {
			detail = count(w.details[source], "directory", "directories")
		} else if strings.HasSuffix(source, "binaries") {
			detail = count(w.details[source], "binary", "binaries")
		}
		w.h.add(source, detail, w.entries[source], w.skipped[source])
	}
	w.h.inv.NotRead = append(w.h.inv.NotRead, FolderNotRead)
	return w.h.inv, nil
}

// dir reads an installed-package directory whole and does not enter it; any other directory is walked.
func (w *folderWalk) dir(path, rel, name string) error {
	if rel != "." && strings.Count(rel, "/") >= maxFolderDepth {
		w.h.inv.NotRead = append(w.h.inv.NotRead, rel+": deeper than "+fmt.Sprint(maxFolderDepth)+" directories")
		return fs.SkipDir
	}
	switch {
	case folderSkip[name]:
		return fs.SkipDir
	case name == "node_modules":
		w.collect("installed npm", rel, nodePackages(path, 0), nil)
		return fs.SkipDir
	case name == "site-packages" || name == "dist-packages":
		w.collect("installed python", rel, pythonPackages(path), nil)
		return fs.SkipDir
	case name == "specifications" && w.gemDir(path):
		w.collect("installed gems", rel, rubyGems(path), nil)
		return fs.SkipDir
	case name == "vendor":
		// Bundler's vendored gems; Go's and Composer's vendor trees are what go.mod and composer.lock name
		for _, spec := range globAll(filepath.Join(path, "bundle", "ruby", "*", "specifications")) {
			w.collect("installed gems", w.rel(spec), rubyGems(spec), nil)
		}
		return fs.SkipDir
	}
	return nil
}

// gemDir is whether a specifications directory holds gemspecs.
func (w *folderWalk) gemDir(path string) bool {
	matches, err := filepath.Glob(filepath.Join(path, "*.gemspec"))
	return err == nil && len(matches) > 0
}

// file reads a lockfile, an SBOM, an MCP configuration or a Go or Rust executable; other files are passed over.
func (w *folderWalk) file(path, rel string, d fs.DirEntry) {
	name := d.Name()
	if parse := lockParserFor(name); parse != nil {
		raw, err := readCapped(path, maxPackageDB)
		if err == nil {
			var r lockResult
			if r, err = parse(raw); err == nil {
				w.collect(rel, rel, r.entries, r.skipped)
				return
			}
		}
		w.notRead(rel, err)
		return
	}
	if dockerfileName(name) || composeName(name) {
		w.images(path, rel, dockerfileName(name))
		return
	}
	if folderSBOM(name) {
		raw, err := readCapped(path, maxUploadFile)
		if err != nil {
			w.notRead(rel, err)
			return
		}
		if entries, _, ok := SBOMEntries(raw); ok {
			w.collect(rel, rel, entries, nil)
		}
		return
	}
	for _, cfg := range folderMCP {
		if rel == cfg || strings.HasSuffix(rel, "/"+cfg) {
			w.mcp(path, rel)
			return
		}
	}
	info, err := d.Info()
	if err != nil || info.Size() < minBinarySize || info.Mode()&0o111 == 0 && !strings.HasSuffix(name, ".exe") {
		return
	}
	if w.binaries >= maxFolderBinaries || !executableFormat(path) {
		return
	}
	w.binaries++
	if mods, renamed, _, ok := goModules(path); ok {
		w.collect("go binaries", rel, mods, nil)
		for _, m := range mods {
			if !renamed[m] {
				w.h.inv.GoBinaries[m] = append(w.h.inv.GoBinaries[m], HostBinary{Path: path, Name: rel})
			}
		}
	} else if crates, ok := rustCrates(path); ok {
		w.collect("rust binaries", rel, crates, nil)
	}
}

// mcp reads the MCP servers a project's own configuration starts: a pinned package is checked, anything else
// listed as not checked.
func (w *folderWalk) mcp(path, rel string) {
	raw, err := readCapped(path, maxConfigFile)
	if err != nil {
		w.notRead(rel, err)
		return
	}
	var entries []string
	var skipped []HostComponent
	for _, s := range launches(path, raw) {
		if s.url != "" {
			continue // a remote server: nothing installed here
		}
		spec, purl, reason := w.h.runnerEntry(filepath.Dir(path), s.command)
		switch {
		case purl != "":
			entries = append(entries, purl)
		case spec != "":
			skipped = append(skipped, HostComponent{Name: spec, Reason: reason})
		}
	}
	if len(entries) > 0 || len(skipped) > 0 {
		w.collect("mcp servers", rel, entries, skipped)
	}
}

// executableFormat is whether a file starts like an ELF, Mach-O or PE executable: anything else (a script, an
// image) is not opened as one.
func executableFormat(path string) bool {
	f, err := openRegular(path)
	if err != nil {
		return false
	}
	magic := make([]byte, 4)
	_, err = io.ReadFull(f, magic)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return false // shorter than any executable, or unreadable
	}
	switch string(magic) {
	case "\x7fELF", "\xcf\xfa\xed\xfe", "\xce\xfa\xed\xfe", "\xfe\xed\xfa\xcf", "\xfe\xed\xfa\xce", "\xca\xfe\xba\xbe":
		return true
	}
	return magic[0] == 'M' && magic[1] == 'Z'
}

// images records the container images a Dockerfile's FROM lines or a Compose file's services name.
func (w *folderWalk) images(path, rel string, dockerfile bool) {
	raw, err := readCapped(path, maxConfigFile)
	if err != nil {
		w.notRead(rel, err)
		return
	}
	var refs, unresolved []string
	if dockerfile {
		refs, unresolved = dockerfileImages(raw)
	} else if refs, unresolved, err = composeImages(raw); err != nil {
		w.notRead(rel, err)
		return
	}
	add := func(ref string, open bool) {
		for i := range w.h.inv.Images {
			if im := &w.h.inv.Images[i]; im.Ref == ref {
				if !slices.Contains(im.Files, rel) {
					im.Files = append(im.Files, rel)
				}
				return
			}
		}
		w.h.inv.Images = append(w.h.inv.Images, FolderImage{Ref: ref, Files: []string{rel}, Unresolved: open})
	}
	for _, ref := range refs {
		add(ref, false)
	}
	for _, ref := range unresolved {
		add(ref, true)
	}
}
