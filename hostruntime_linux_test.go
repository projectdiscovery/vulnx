package vulnx

import (
	"context"
	"net"
	"os"
	"slices"
	"testing"
)

func TestRuntimeLinuxLiveListeners(t *testing.T) {
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
	inv.collectRuntime(context.Background(), "", collectHostRuntime)
	for protocol, port := range map[string]uint16{"tcp": uint16(tcp.Addr().(*net.TCPAddr).Port), "udp": uint16(udp.LocalAddr().(*net.UDPAddr).Port)} {
		found := false
		for _, e := range inv.Runtime.Endpoints {
			if e.Protocol == protocol && e.Port == port && e.Address == "127.0.0.1" && slices.Contains(e.Owners, os.Getpid()) {
				found = true
				if e.Bind != "loopback" || (protocol == "tcp" && e.State != "listening") || (protocol == "udp" && e.State != "bound") {
					t.Fatalf("wrong endpoint: %+v", e)
				}
			}
		}
		if !found {
			t.Fatalf("missing own %s endpoint; gaps=%+v", protocol, inv.Runtime.Gaps)
		}
	}
	found := false
	for _, p := range inv.Runtime.Processes {
		if p.PID == os.Getpid() {
			found = true
			if p.Executable == "" || p.image == nil || p.EffectiveUID == nil || *p.EffectiveUID != uint32(os.Geteuid()) {
				t.Fatalf("own process metadata: %+v; gaps=%+v", p, inv.Runtime.Gaps)
			}
		}
	}
	if !found {
		t.Fatal("own process missing")
	}
}
