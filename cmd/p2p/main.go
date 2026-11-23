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
	case "nat-check", "connect", "mesh":
		// Legacy p2p-client style: keep the top-level client subcommands
		// working directly on the unified binary.
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
	fmt.Println(`p2p — unified P2P client/server CLI

usage:
  p2p server [options]                  run signaling + STUN + relay server
  p2p client <nat-check|connect|mesh>   run the client
  p2p <nat-check|connect|mesh>          compatibility form of the client

examples:
  p2p server --public <public-ip> --port 8080
  p2p client mesh --server <server-ip>:8080 --room demo
  p2p client nat-check --server <server-ip>:8080

help:
  p2p server --help
  p2p client --help
  p2p client mesh --help

compatibility:
  The executable may also be renamed to p2p-server or p2p-client; the
  invoked name selects the role automatically.`)
}
