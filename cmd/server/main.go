// Command server is a thin compatibility wrapper around the unified p2p CLI.
// Building ./cmd/p2p is preferred; this entry point keeps the legacy
// p2p-server binary name and behavior.
package main

import (
	"os"

	"p2p/cmd/internal/cli"
)

func main() {
	os.Exit(cli.RunServer(os.Args[1:]))
}
