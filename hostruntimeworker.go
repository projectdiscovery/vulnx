package vulnx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// HostRuntimeWorkerArg is the argument the CLI starts itself with to run the runtime worker.
const HostRuntimeWorkerArg = "--internal-host-runtime-worker"

// runtimeWireLimit bounds each direction of the worker's pipe.
const runtimeWireLimit = 8 << 20

// runtimeRequest is what the worker needs of the inventory: the entries already found (not added twice), the
// places and their paths (an executable at a known place is named by it), and the Go binaries (the names of the
// executables already read).
type runtimeRequest struct {
	Entries    []string                `json:"entries"`
	Paths      map[string]string       `json:"paths"`
	GoBinaries map[string][]HostBinary `json:"go_binaries"`
}

// runtimeReply is one message from the worker: the snapshot as observed, then with the executables read
// (enriched, with the additions to the inventory).
type runtimeReply struct {
	Phase     string            `json:"phase"` // observed | enriched
	Runtime   *HostRuntime      `json:"runtime"`
	Additions *runtimeAdditions `json:"additions,omitempty"`
}

// RunHostRuntimeWorker is the runtime worker: it reads a runtimeRequest, takes the snapshot and reads the
// observed executables, answering after each. Only the CLI's worker entry point calls it.
func RunHostRuntimeWorker(input io.Reader, output io.Writer) error {
	raw, err := io.ReadAll(io.LimitReader(input, runtimeWireLimit+1))
	if err != nil {
		return err
	}
	if len(raw) > runtimeWireLimit {
		return fmt.Errorf("runtime worker input exceeds limit")
	}
	var request runtimeRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		return err
	}
	inv := HostInventory{Entries: request.Entries, Paths: request.Paths, GoBinaries: request.GoBinaries}
	ctx, cancel := context.WithTimeout(context.Background(), runtimeWorkerBudget)
	defer cancel()
	inv.collectRuntime(ctx, "", collectHostRuntime)
	enc := json.NewEncoder(output)
	if err := enc.Encode(runtimeReply{Phase: "observed", Runtime: inv.Runtime}); err != nil {
		return err
	}
	r := inv.Runtime
	if r.Status == "skipped" {
		return enc.Encode(runtimeReply{Phase: "enriched", Runtime: r, Additions: &runtimeAdditions{}})
	}
	additions := inv.runtimeAdditions(ctx, func(f *os.File) runtimeModules { return readRuntimeModules(f) })
	inv.applyRuntimeAdditions(additions)
	inv.matchRuntime(ctx, r)
	r.normalize()
	return enc.Encode(runtimeReply{Phase: "enriched", Runtime: r, Additions: &additions})
}

// CollectRuntimeIsolated takes the runtime snapshot in a worker: the current executable started with
// HostRuntimeWorkerArg. Killing the worker bounds even filesystem calls and binary parsers that cannot observe a
// context. A mounted root is not this machine's runtime: the snapshot is marked skipped.
func (inv *HostInventory) CollectRuntimeIsolated(ctx context.Context, root string) {
	if mountedRoot(root) {
		inv.collectRuntime(ctx, root, nil)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, runtimeBudget)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		inv.Runtime = newHostRuntime("unavailable", "isolated local runtime collection")
		inv.Runtime.gap("worker", 0, err.Error())
		inv.Runtime.FinishedAt = inv.Runtime.StartedAt
		return
	}
	inv.collectRuntimeWorker(ctx, executable, []string{HostRuntimeWorkerArg})
}

func (inv *HostInventory) collectRuntimeWorker(ctx context.Context, executable string, args []string) {
	inv.Runtime = newHostRuntime("unavailable", "isolated local runtime collection")
	fail := func(reason string) {
		inv.Runtime.gap("worker", 0, reason)
		inv.Runtime.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	input, err := json.Marshal(runtimeRequest{Entries: inv.Entries, Paths: inv.Paths, GoBinaries: inv.GoBinaries})
	if err != nil {
		fail(err.Error())
		return
	}
	if len(input) > runtimeWireLimit {
		fail("runtime worker input exceeds limit")
		return
	}
	cmd := newCommand(ctx, executable, args...)
	cmd.Stdin = bytes.NewReader(input)
	stdout, stderr := &cappedBuffer{limit: runtimeOutputLimit}, &cappedBuffer{limit: runtimeOutputLimit}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	runErr := cmd.Run() // at ctx's end the worker's process group is killed
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	phase := ""
	for {
		var reply runtimeReply
		err := decoder.Decode(&reply)
		if err == io.EOF {
			break
		}
		if err != nil {
			fail("incomplete or invalid runtime worker output")
			break
		}
		valid := reply.Runtime != nil && (reply.Phase == "observed" || reply.Phase == "enriched" && reply.Additions != nil)
		if !valid {
			fail("invalid runtime worker response")
			break
		}
		inv.Runtime = reply.Runtime
		if reply.Phase == "enriched" {
			inv.applyRuntimeAdditions(*reply.Additions)
		}
		phase = reply.Phase
	}
	if stdout.Truncated() || stderr.Truncated() {
		fail("runtime worker output exceeds limit")
	}
	if runErr != nil {
		if ctx.Err() != nil {
			fail("runtime worker stopped: " + ctx.Err().Error())
		} else {
			fail("runtime worker failed: " + runErr.Error())
		}
	} else if phase != "enriched" {
		fail("runtime worker did not complete inventory enrichment")
	}
	if stderr.Len() > 0 {
		fail("runtime worker reported diagnostic output")
	}
}
