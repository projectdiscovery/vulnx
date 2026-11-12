package vulnx

import (
	"archive/zip"
	"bytes"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// writeTorchArchive writes the archive PyTorch saves: a zip whose data.pkl is the pickle.
func writeTorchArchive(t *testing.T, root, rel string, pickle []byte) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string][]byte{"model/data.pkl": pickle, "model/data/0": {0, 0, 0, 0}} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, rel, buf.String())
}

var (
	// what a saved state dict imports: nothing that runs a command
	plainPickle = []byte("\x80\x02ccollections\nOrderedDict\nq\x00)Rq\x01ctorch._utils\n_rebuild_tensor_v2\nq\x02.")
	// protocol 2: GLOBAL os system
	systemPickle = []byte("\x80\x02cposix\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03.")
	// protocol 4: STACK_GLOBAL over two short strings
	evalPickle = []byte("\x80\x04\x95\x1e\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x94\x8c\x011\x94\x85\x94R\x94.")
	// the same import with no MEMOIZE between, and a harmless one of the same module
	bareEvalPickle = []byte("\x80\x04\x8c\x08builtins\x8c\x03set\x93\x8c\x02os\x8c\x06system\x93.")
)

func TestPickleImports(t *testing.T) {
	root := t.TempDir()
	writeTorchArchive(t, root, "plain.pt", plainPickle)
	writeTorchArchive(t, root, "system.pt", systemPickle)
	writeFile(t, root, "eval.pkl", string(evalPickle))
	writeFile(t, root, "bare.pkl", string(bareEvalPickle))
	writeFile(t, root, "weights.bin", "GGUF\x03\x00\x00\x00 not a pickle")
	writeFile(t, root, "empty.pt", "")
	for name, want := range map[string]struct {
		pickle  bool
		imports string
	}{"plain.pt": {true, ""}, "system.pt": {true, "posix.system"}, "eval.pkl": {true, "builtins.eval"}, "bare.pkl": {true, "os.system"},
		"weights.bin": {false, ""}, "empty.pt": {false, ""}, "missing.pt": {false, ""}} {
		pickle, imports := pickleImports(filepath.Join(root, name))
		if pickle != want.pickle || imports != want.imports {
			t.Errorf("%s: got %v %q, want %v %q", name, pickle, imports, want.pickle, want.imports)
		}
	}
}

func TestLocalModels(t *testing.T) {
	root := t.TempDir()
	hub := "home/dev/.cache/huggingface/hub/"
	writeFile(t, root, hub+"models--Good--Safe/snapshots/abc/model.safetensors", "x")
	writeFile(t, root, hub+"models--Good--Safe/snapshots/abc/config.json", `{"model_type": "qwen"}`)
	writeTorchArchive(t, root, hub+"models--Old--Torch/snapshots/abc/pytorch_model.bin", plainPickle)
	writeTorchArchive(t, root, hub+"models--Evil--Model/snapshots/abc/pytorch_model.bin", systemPickle)
	writeFile(t, root, hub+"models--Own--Code/snapshots/abc/model.safetensors", "x")
	writeFile(t, root, hub+"models--Own--Code/snapshots/abc/config.json", `{"auto_map": {"AutoModel": "modeling_own.OwnModel"}}`)
	writeFile(t, root, hub+"models--Own--Code/snapshots/abc/modeling_own.py", "class OwnModel: ...\n")
	writeFile(t, root, hub+"models--Helper--Script/snapshots/abc/model.safetensors", "x")
	writeFile(t, root, hub+"models--Helper--Script/snapshots/abc/convert.py", "print(1)\n")
	writeFile(t, root, hub+"datasets--Some--Data/snapshots/abc/data.parquet", "x")
	writeFile(t, root, "home/dev/.lmstudio/models/pub/Model-GGUF/model.gguf", "GGUF")
	writeFile(t, root, "home/dev/.ollama/models/manifests-v2/ollama.com/library/qwen3/latest", "{}")
	writeFile(t, root, "home/dev/.ollama/models/manifests/registry.ollama.ai/someone/tuned/v2", "{}")
	writeFile(t, root, "home/dev/.lmstudio/extensions/backends/llama.cpp-linux-2.71.0/backend-manifest.json", `{"version": "2.71.0", "engine": "llama.cpp"}`)
	writeFile(t, root, "home/dev/.lmstudio/.internal/http-server.json", `{"host": "0.0.0.0", "port": 1234}`)
	writeFile(t, root, "home/dev/.zshrc", "# export OLLAMA_HOST=0.0.0.0\nexport OLLAMA_HOST=127.0.0.1:11434\n")
	writeFile(t, root, "etc/systemd/system/ollama.service.d/override.conf", "[Service]\nEnvironment=\"OLLAMA_HOST=0.0.0.0:11434\"\n")
	writeFile(t, root, "home/dev/Library/LaunchAgents/homebrew.mxcl.ollama.plist",
		"<dict>\n<key>EnvironmentVariables</key>\n<dict>\n<key>OLLAMA_HOST</key>\n<string>192.168.1.5</string>\n</dict></dict>")

	h := newHostReader(root, "linux")
	h.localModels()

	var models []string
	for _, it := range h.inv.AgentSurface {
		if it.Kind == "model" {
			models = append(models, it.Name)
		}
	}
	sort.Strings(models)
	if want := []string{"Evil/Model", "Good/Safe", "Helper/Script", "Old/Torch", "Own/Code", "pub/Model-GGUF", "qwen3:latest", "someone/tuned:v2"}; !reflect.DeepEqual(models, want) {
		t.Fatalf("models %q", models)
	}
	var risks []string
	details := map[string]string{}
	for _, r := range h.inv.Risks {
		risks = append(risks, r.Risk+" "+r.Kind+" "+r.Name)
		details[r.Risk+" "+r.Name] = r.Detail
	}
	sort.Strings(risks)
	want := []string{"custom_code model Own/Code", "exposed runtime LM Studio", "exposed runtime Ollama", "exposed runtime Ollama",
		"model_runs_commands model Evil/Model", "pickle_format model Old/Torch"}
	if !reflect.DeepEqual(risks, want) {
		t.Fatalf("risks:\n got %q\nwant %q", risks, want)
	}
	if got := details["model_runs_commands Evil/Model"]; got != "pytorch_model.bin imports posix.system when loaded" {
		t.Fatalf("detail %q", got)
	}
	if src := h.inv.Sources[0]; src.Name != modelSource || src.Detail != "1 bundled engine, 8 models" || src.NotAssessed != 1 {
		t.Fatalf("source %+v", src)
	}
}

func TestLoopback(t *testing.T) {
	for addr, want := range map[string]bool{"127.0.0.1": true, "127.0.0.1:11434": true, "localhost": true, "localhost:11434": true,
		"[::1]:11434": true, "http://127.0.0.1:11434": true, "0.0.0.0": false, "0.0.0.0:11434": false, "::": false,
		"192.168.1.5": false, "http://0.0.0.0:11434/": false, "myhost.lan:11434": false, ":11434": false} {
		if got := loopback(addr); got != want {
			t.Errorf("%s: got %v", addr, got)
		}
	}
}
