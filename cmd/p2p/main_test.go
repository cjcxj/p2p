package main

import "testing"

func TestRunDispatchAndHelp(t *testing.T) {
	if code := run("p2p", nil); code != 2 {
		t.Fatalf("empty args: got %d, want 2", code)
	}
	if code := run("p2p", []string{"--help"}); code != 0 {
		t.Fatalf("--help: got %d, want 0", code)
	}
	if code := run("p2p", []string{"up", "--help"}); code != 0 {
		t.Fatalf("up --help: got %d, want 0", code)
	}
	if code := run("p2p", []string{"join", "--help-advanced"}); code != 0 {
		t.Fatalf("join --help-advanced: got %d, want 0", code)
	}
	if code := run("p2p-client", []string{"up", "--help"}); code != 0 {
		t.Fatalf("p2p-client argv0 dispatch: got %d, want 0", code)
	}
	if code := run("p2p", []string{"unknown-subcmd"}); code != 2 {
		t.Fatalf("unknown subcommand: got %d, want 2", code)
	}
}
