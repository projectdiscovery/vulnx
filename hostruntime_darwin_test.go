//go:build darwin

package vulnx

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"
)

func TestRuntimeSocketCommand(t *testing.T) {
	for _, tc := range []struct {
		name, script    string
		warning, failed bool
	}{
		{"empty", "exit 1", false, false},
		{"failure", "exit 2", false, true},
		{"warning", "printf warning >&2; exit 1", true, true},
		{"partial", "printf 'p1\\000'; exit 1", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fixture")
			if err := os.WriteFile(path, []byte("#!/bin/sh\n"+tc.script+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			_, warning, err := runRuntimeSocketCommand(context.Background(), path, nil)
			if warning != tc.warning || (err != nil) != tc.failed {
				t.Fatalf("warning=%v error=%v", warning, err)
			}
		})
	}
	if _, _, err := runRuntimeSocketCommand(context.Background(), "/nonexistent/runtime-collector", nil); err == nil {
		t.Fatal("missing utility accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := runRuntimeSocketCommand(ctx, "/usr/sbin/lsof", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
	var buf runtimeBuffer
	input := bytes.Repeat([]byte{'x'}, (8<<20)+1)
	if n, err := buf.Write(input); err != nil || n != len(input) || !buf.truncated || buf.Len() != 8<<20 {
		t.Fatalf("bounded output: %d %v", n, err)
	}
}

func TestRuntimeProcess(t *testing.T) {
	p, err := runtimeProcess(context.Background(), os.Getpid(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.PID != os.Getpid() || p.Identity == "" || p.Executable == "" || p.EffectiveUID == nil || *p.EffectiveUID != uint32(os.Geteuid()) {
		t.Fatalf("%+v", p)
	}
	if _, err := runtimeProcess(context.Background(), os.Getpid(), time.Unix(0, 0)); err == nil {
		t.Fatal("unverified process generation accepted")
	}
	if _, err := runtimeProcess(context.Background(), 2147483647, time.Now()); err == nil {
		t.Fatal("missing process accepted")
	}
}

func TestRuntimeImageMatches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image")
	if err := os.WriteFile(path, []byte("old"), 0700); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	native := st.Sys().(*syscall.Stat_t)
	images := []runtimeImage{{path: path, device: uint64(uint32(native.Dev)), inode: native.Ino}}
	if runtimeImageInfo(path, images) == nil {
		t.Fatal("exact mapped image rejected")
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("new"), 0700); err != nil {
		t.Fatal(err)
	}
	if runtimeImageInfo(path, images) != nil {
		t.Fatal("replaced executable accepted")
	}
	if runtimeImageInfo(path, nil) != nil {
		t.Fatal("missing mapped image accepted")
	}
}

func TestRuntimeLiveListeners(t *testing.T) {
	if _, err := os.Stat("/usr/sbin/lsof"); err != nil {
		t.Skipf("socket enumerator unavailable: %v", err)
	}
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := tcp.Close(); err != nil {
			t.Error(err)
		}
	})
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := udp.Close(); err != nil {
			t.Error(err)
		}
	})
	var inv HostInventory
	inv.CollectRuntime(context.Background(), "")
	want := map[string]uint16{"tcp": uint16(tcp.Addr().(*net.TCPAddr).Port), "udp": uint16(udp.LocalAddr().(*net.UDPAddr).Port)}
	for protocol, port := range want {
		found := false
		for _, e := range inv.Runtime.Endpoints {
			if e.Protocol == protocol && e.Port == port && e.Address == "127.0.0.1" && slices.Contains(e.Owners, os.Getpid()) {
				found = true
				if e.Bind != "loopback" {
					t.Fatalf("%+v", e)
				}
			}
		}
		if !found {
			t.Fatalf("missing test-owned %s port %d; gaps=%+v", protocol, port, inv.Runtime.Gaps)
		}
	}
	found := false
	for _, p := range inv.Runtime.Processes {
		if p.PID == os.Getpid() {
			found = true
			if p.Executable == "" || p.EffectiveUID == nil {
				t.Fatalf("%+v", p)
			}
		}
	}
	if !found {
		t.Fatal("test-owned process missing")
	}
	t.Logf("observed %d endpoints and %d owner processes; status %s; %d explicit gaps", len(inv.Runtime.Endpoints), len(inv.Runtime.Processes), inv.Runtime.Status, len(inv.Runtime.Gaps))
}
