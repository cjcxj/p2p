// Command p2p is the unified CLI for the P2P stack. One binary contains both
// the server and the client; the role is selected by subcommand or, for
// compatibility with the previous p2p-server / p2p-client distribution, by
// the name the binary was invoked as.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"p2p/cmd/internal/cli"
)

func main() {
	os.Exit(run(os.Args[0], os.Args[1:]))
}

func run(argv0 string, args []string) int {
	base := strings.ToLower(filepath.Base(argv0))

	// Compatibility with the legacy binary names: the same executable may be
	// installed as p2p-server / p2p-client (e.g. p2p-server-linux,
	// p2p-client.exe).
	if strings.HasPrefix(base, "p2p-server") {
		return cli.RunServer(args)
	}
	if strings.HasPrefix(base, "p2p-client") {
		return cli.RunClient(args)
	}

	if len(args) < 1 {
		usage()
		return 2
	}
	switch args[0] {
	case "server":
		return cli.RunServer(args[1:])
	case "client":
		return cli.RunClient(args[1:])
	case "up", "join", "nat-check", "connect", "mesh":
		return cli.RunClient(args)
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		usage()
		return 2
	}
}

func usage() {
	fmt.Println(`p2p — pure-P2P WireGuard mesh networking

quickstart:
  p2p server [--stun-servers stun1:3478,stun2:3478]
  p2p up <server[:port]> <room> [--secret <s>]
  p2p nat-check <server[:port]>

commands:
  server     run single signaling + STUN server
  up, join   join a virtual network with WireGuard TUN enabled (recommended)
  nat-check  diagnose local NAT type and carrier egress pool
  mesh       virtual network console (accepts --tun; legacy compatible)
  connect    raw probe/text mode (legacy compatible)

examples:
  p2p server --port 8080 --stun-servers stun.miwifi.com:3478,stun.chat.bilibili.com:3478
  p2p up 1.2.3.4:8080 demo
  p2p up p2p://1.2.3.4:8080/demo
  p2p nat-check 1.2.3.4:8080

help:
  p2p server --help
  p2p up --help
  p2p up --help-advanced`)
}
