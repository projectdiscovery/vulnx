package vulnx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const HostRuntimeWorkerArg = "--internal-host-runtime-worker"
const runtimeWireLimit = 8 << 20

// runtimeWire carries fields omitted from public inventory JSON across the local process boundary.
type runtimeWire struct {
	Phase       string                  `json:"phase"`
	Host        HostInventory           `json:"host"`
	Entries     []string                `json:"entries"`
	EntrySource map[string]string       `json:"entry_source"`
	GoBinaries  map[string][]HostBinary `json:"go_binaries"`
	LocalPlaces map[string]bool         `json:"local_places"`
}

func (inv HostInventory) runtimeWire(phase string) runtimeWire {
	return runtimeWire{Phase: phase, Host: inv, Entries: inv.Entries, EntrySource: inv.EntrySource, GoBinaries: inv.GoBinaries, LocalPlaces: inv.runtimePlaces}
}

func (w runtimeWire) inventory() HostInventory {
	inv := w.Host
	inv.Entries, inv.EntrySource, inv.GoBinaries, inv.runtimePlaces = w.Entries, w.EntrySource, w.GoBinaries, w.LocalPlaces
	return inv
}

func (inv *HostInventory) applyRuntimeWire(w runtimeWire) {
	update := w.inventory()
	inv.Runtime = update.Runtime
	inv.Runtime.enriched = w.Phase == "enriched"
	if w.Phase != "enriched" {
		return
	}
	inv.Entries, inv.EntrySource, inv.GoBinaries, inv.runtimePlaces = update.Entries, update.EntrySource, update.GoBinaries, update.runtimePlaces
	inv.FoundIn, inv.Paths, inv.Fixes = update.FoundIn, update.Paths, update.Fixes
	inv.Sources, inv.NotAssessed = update.Sources, update.NotAssessed
	h := hostReader{inv: *inv}
	inv.Note = h.note()
}

// RunHostRuntimeWorker is only dispatched by the CLI's private worker entry point.
func RunHostRuntimeWorker(input io.Reader, output io.Writer) error {
	raw, err := io.ReadAll(io.LimitReader(input, runtimeWireLimit+1))
	if err != nil {
		return err
	}
	if len(raw) > runtimeWireLimit {
		return fmt.Errorf("runtime worker input exceeds limit")
	}
	var request runtimeWire
	if err := json.Unmarshal(raw, &request); err != nil {
		return err
	}
	inv := request.inventory()
	ctx, cancel := context.WithTimeout(context.Background(), runtimeBudget)
	defer cancel()
	inv.CollectRuntime(ctx, "")
	enc := json.NewEncoder(output)
	if err := enc.Encode(inv.runtimeWire("observed")); err != nil {
		return err
	}
	inv.EnrichRuntimeInventory(ctx)
	return enc.Encode(inv.runtimeWire("enriched"))
}

// CollectRuntimeIsolated requires the current executable to dispatch HostRuntimeWorkerArg.
// Killing the worker bounds even filesystem calls and binary parsers that cannot observe a Go context.
func (inv *HostInventory) CollectRuntimeIsolated(ctx context.Context, root string) {
	if root != "" && filepath.Clean(root) != filepath.Clean("/") {
		inv.CollectRuntime(ctx, root)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, runtimeBudget)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		inv.Runtime = &HostRuntime{StartedAt: now, FinishedAt: now, Status: "unavailable", Scope: "isolated local runtime collection", Gaps: []HostRuntimeGap{{Stage: "worker", Reason: err.Error()}}, Endpoints: []HostEndpoint{}, Processes: []HostProcess{}}
		return
	}
	inv.collectRuntimeWorker(ctx, executable, []string{HostRuntimeWorkerArg})
}

func (inv *HostInventory) collectRuntimeWorker(ctx context.Context, executable string, args []string) {
	inv.Runtime = &HostRuntime{StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Status: "unavailable", Scope: "isolated local runtime collection", Endpoints: []HostEndpoint{}, Processes: []HostProcess{}, Gaps: []HostRuntimeGap{}}
	fail := func(reason string) {
		inv.Runtime.gap("worker", 0, reason)
		inv.Runtime.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	input, err := json.Marshal(inv.runtimeWire("request"))
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
	finished := make(chan error, 1)
	go func() { finished <- cmd.Run() }()
	var runErr error
	select {
	case runErr = <-finished:
	case <-ctx.Done():
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case runErr = <-finished:
			timer.Stop()
		case <-timer.C:
			runErr = ctx.Err()
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	phase := ""
	for {
		var result runtimeWire
		err := decoder.Decode(&result)
		if err == io.EOF {
			break
		}
		if err != nil {
			fail("incomplete or invalid runtime worker output")
			break
		}
		if result.Host.Runtime == nil || (result.Phase != "observed" && result.Phase != "enriched") {
			fail("invalid runtime worker response")
			break
		}
		inv.applyRuntimeWire(result)
		phase = result.Phase
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
