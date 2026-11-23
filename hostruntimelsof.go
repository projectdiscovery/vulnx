package vulnx

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type runtimeImage struct {
	path   string
	device uint64
	inode  uint64
}

func parseRuntimeImages(raw []byte) map[int][]runtimeImage {
	out := map[int][]runtimeImage{}
	pid := 0
	fields := map[byte]string{}
	flush := func() {
		if pid > 0 && fields['n'] != "" {
			device, devErr := strconv.ParseUint(fields['D'], 0, 64)
			inode, inoErr := strconv.ParseUint(fields['i'], 10, 64)
			if devErr == nil && inoErr == nil {
				out[pid] = append(out[pid], runtimeImage{path: fields['n'], device: device, inode: inode})
			}
		}
		fields = map[byte]string{}
	}
	for _, token := range bytes.Split(raw, []byte{0}) {
		token = bytes.TrimLeft(token, "\n")
		if len(token) == 0 {
			continue
		}
		key, value := token[0], string(token[1:])
		switch key {
		case 'p':
			flush()
			n, err := strconv.Atoi(value)
			if err != nil {
				pid = 0
			} else {
				pid = n
			}
		case 'f':
			flush()
		case 'n', 'D', 'i':
			fields[key] = value
		}
	}
	flush()
	return out
}

func parseRuntimeSockets(raw []byte) ([]HostEndpoint, error) {
	var out []HostEndpoint
	pid := 0
	fields := map[byte]string{}
	malformed := false
	flush := func() {
		if len(fields) == 0 {
			return
		}
		defer func() { fields = map[byte]string{} }()
		proto := strings.ToLower(fields['P'])
		if proto != "tcp" && proto != "udp" {
			malformed = true
			return
		}
		if proto == "tcp" && fields['T'] != "ST=LISTEN" {
			if fields['T'] == "" {
				malformed = true
			}
			return
		}
		family := strings.ToLower(fields['t'])
		if family != "ipv4" && family != "ipv6" {
			malformed = true
			return
		}
		local, peer, connected := strings.Cut(fields['n'], "->")
		if proto == "udp" && connected && peer != "" { // a client's socket, connected to its one peer
			return
		}
		host, portText, err := net.SplitHostPort(local)
		if err != nil {
			malformed = true
			return
		}
		if host == "*" {
			if family == "ipv6" {
				host = "::"
			} else {
				host = "0.0.0.0"
			}
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			malformed = true
			return
		}
		if proto == "udp" && portText == "*" {
			return
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil {
			malformed = true
			return
		}
		if port == 0 {
			return
		}
		// the socket's kernel address: shared by every process holding the socket (a forked server's workers)
		e := HostEndpoint{Protocol: proto, Family: family, Address: ip.String(), Port: uint16(port), State: "bound", Owners: []int{}, Socket: fields['d']}
		if proto == "tcp" {
			e.State = "listening"
		}
		if pid > 0 {
			e.Owners = append(e.Owners, pid)
		} else {
			malformed = true
		}
		out = append(out, e)
	}
	for _, token := range bytes.Split(raw, []byte{0}) {
		token = bytes.TrimLeft(token, "\n")
		if len(token) == 0 {
			continue
		}
		key, value := token[0], string(token[1:])
		switch key {
		case 'p':
			flush()
			n, err := strconv.Atoi(value)
			pid = n
			if err != nil || n <= 0 {
				pid = 0
				malformed = true
			}
		case 'f':
			flush()
			fields[key] = value
		case 'P', 't', 'n', 'd':
			fields[key] = value
		case 'T':
			if strings.HasPrefix(value, "ST=") {
				fields[key] = value
			}
		}
	}
	flush()
	if len(raw) > 0 && raw[len(raw)-1] != 0 && raw[len(raw)-1] != '\n' {
		malformed = true
	}
	if malformed {
		return out, fmt.Errorf("some socket records were malformed or incomplete")
	}
	return out, nil
}
