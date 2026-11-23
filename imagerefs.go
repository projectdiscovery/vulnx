package vulnx

// The container images a folder's Dockerfiles and Compose files name, read here: a folder scan lists them, and
// with --images sends each name to SecurityContext's image scan.

import (
	"bufio"
	"bytes"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// FolderImage is a container image a folder names: its reference and the files that name it (relative paths).
// Unresolved is set when the reference holds a variable with no value given; Ref is then the text as written.
type FolderImage struct {
	Ref        string   `json:"ref"`
	Files      []string `json:"files"`
	Unresolved bool     `json:"unresolved,omitempty"`
}

// imageVar is a variable in a Dockerfile or Compose file: ${NAME}, ${NAME:-default}, ${NAME-default} or $NAME.
var imageVar = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?-)([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// expandImageVars expands the variables in s from vars and the defaults written in s; ok is false when a variable
// has neither.
func expandImageVars(s string, vars map[string]string) (string, bool) {
	ok := true
	out := imageVar.ReplaceAllStringFunc(s, func(m string) string {
		g := imageVar.FindStringSubmatch(m)
		name := g[1] + g[4]
		if v, set := vars[name]; set && (v != "" || g[2] != ":-") {
			return v
		}
		if g[2] != "" {
			return g[3]
		}
		ok = false
		return m
	})
	return out, ok
}

// dockerfileLines joins a Dockerfile's continued lines and drops its comments.
func dockerfileLines(raw []byte) []string {
	var lines []string
	var cur strings.Builder
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t\r")
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if body, ok := strings.CutSuffix(line, `\`); ok {
			cur.WriteString(body + " ")
			continue
		}
		cur.WriteString(line)
		if s := strings.TrimSpace(cur.String()); s != "" {
			lines = append(lines, s)
		}
		cur.Reset()
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		lines = append(lines, s)
	}
	return lines
}

// dockerfileImages reads the images a Dockerfile's FROM lines name: a build stage's name is not an image, scratch
// is none, and an ARG's default (before the first FROM, or in the stage) fills a variable.
func dockerfileImages(raw []byte) (refs, unresolved []string) {
	vars := map[string]string{}
	stages := map[string]bool{}
	add := func(list *[]string, s string) {
		if !slices.Contains(*list, s) {
			*list = append(*list, s)
		}
	}
	for _, line := range dockerfileLines(raw) {
		fields := strings.Fields(line)
		switch strings.ToUpper(fields[0]) {
		case "ARG":
			for _, f := range fields[1:] {
				// ARG NAME with no default leaves NAME to a build argument: unset here
				if name, value, ok := strings.Cut(f, "="); ok {
					vars[name] = strings.Trim(value, `"'`)
				}
			}
		case "FROM":
			args := fields[1:]
			for len(args) > 0 && strings.HasPrefix(args[0], "--") { // --platform=linux/amd64
				args = args[1:]
			}
			if len(args) == 0 {
				continue
			}
			image := args[0]
			ref, ok := expandImageVars(image, vars)
			switch {
			case !ok:
				add(&unresolved, image)
			case stages[strings.ToLower(ref)] || strings.EqualFold(ref, "scratch"):
				// an earlier stage, or no image at all
			default:
				add(&refs, ref)
			}
			if len(args) >= 3 && strings.EqualFold(args[1], "AS") {
				stages[strings.ToLower(args[2])] = true
			}
		}
	}
	return refs, unresolved
}

// composeImages reads the images a Compose file's services run: a service built here (with build:) runs what it
// builds, its image: only the tag that build is given, so it is not an image to pull.
func composeImages(raw []byte) (refs, unresolved []string, err error) {
	var doc struct {
		Services map[string]struct {
			Image string `yaml:"image"`
			Build any    `yaml:"build"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, nil, err
	}
	for _, name := range sortedKeys(doc.Services) {
		s := doc.Services[name]
		if s.Image == "" || s.Build != nil {
			continue
		}
		ref, ok := expandImageVars(s.Image, nil)
		list := &refs
		if !ok {
			list, ref = &unresolved, s.Image
		}
		if !slices.Contains(*list, ref) {
			*list = append(*list, ref)
		}
	}
	return refs, unresolved, nil
}

// dockerfileName is whether a file name is a Dockerfile's: Dockerfile, Containerfile, *.Dockerfile, Dockerfile.*.
func dockerfileName(name string) bool {
	n := strings.ToLower(name)
	// Dockerfile.dev as written: dockerfile.go is source code
	return n == "dockerfile" || n == "containerfile" || strings.HasSuffix(n, ".dockerfile") ||
		strings.HasPrefix(name, "Dockerfile.") || strings.HasPrefix(name, "Containerfile.")
}

// composeName is whether a file name is a Compose file's: compose.yaml, compose.*.yaml, docker-compose*.yaml (or
// .yml).
func composeName(name string) bool {
	n := strings.ToLower(name)
	if !strings.HasSuffix(n, ".yaml") && !strings.HasSuffix(n, ".yml") {
		return false
	}
	base := strings.TrimSuffix(strings.TrimSuffix(n, ".yaml"), ".yml")
	return base == "compose" || strings.HasPrefix(base, "compose.") || strings.HasPrefix(base, "docker-compose")
}
