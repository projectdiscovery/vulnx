package vulnx

import "testing"

func TestParseRuntimeImages(t *testing.T) {
	images := parseRuntimeImages([]byte("p42\x00\nftxt\x00D0x100000d\x00i123\x00n/bin/tool\x00\nftxt\x00Dbad\x00i456\x00n/ignored\x00\npbad\x00ftxt\x00D0x1\x00i3\x00n/ignored\x00"))
	if len(images) != 1 || len(images[42]) != 1 || images[42][0].path != "/bin/tool" || images[42][0].inode != 123 || images[42][0].device != 0x100000d {
		t.Fatalf("%+v", images)
	}
}

func TestParseRuntimeSockets(t *testing.T) {
	raw := "p42\x00u501\x00\nf1\x00tIPv4\x00PTCP\x00n*:8080\x00TST=LISTEN\x00TQR=0\x00\nf2\x00tIPv6\x00PTCP\x00n[::1]:443\x00TST=LISTEN\x00\nf3\x00tIPv4\x00PTCP\x00n127.0.0.1:1000->127.0.0.1:2000\x00TST=ESTABLISHED\x00\nf4\x00tIPv6\x00PUDP\x00n*:5353\x00\nf5\x00tIPv4\x00PUDP\x00n127.0.0.1:53->127.0.0.1:5000\x00\n"
	got, err := parseRuntimeSockets([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got[0].Address != "0.0.0.0" || got[0].Port != 8080 || got[0].Owners[0] != 42 || got[1].Address != "::1" || got[2].Address != "::" || got[2].State != "bound" || got[3].Address != "127.0.0.1" {
		t.Fatalf("%+v", got)
	}
}

func TestParseRuntimeSocketsMalformed(t *testing.T) {
	for _, raw := range []string{
		"pbad\x00f1\x00tIPv4\x00PUDP\x00n*:53\x00",
		"p42\x00f1\x00tIPv4\x00PUDP\x00nbad:53\x00",
		"p42\x00f1\x00tIPv4\x00PUDP\x00n*:99999\x00",
		"p42\x00f1\x00tIPv4\x00PUDP\x00n*:53",
		"p42\x00f1\x00tIPv4\x00PUDP\x00",
	} {
		if _, err := parseRuntimeSockets([]byte(raw)); err == nil {
			t.Errorf("accepted malformed %q", raw)
		}
	}
	for _, raw := range []string{"", "p42\x00f1\x00tIPv4\x00PUDP\x00n*:0\x00", "p42\x00f1\x00tIPv4\x00PUDP\x00n*:*\x00"} {
		out, err := parseRuntimeSockets([]byte(raw))
		if err != nil || len(out) != 0 {
			t.Fatalf("%q: %+v %v", raw, out, err)
		}
	}
}
