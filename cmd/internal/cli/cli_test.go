package cli

import (
	"testing"
)

func TestParseClientOptionsModesAndDefaults(t *testing.T) {
	upOpts, helpKind, err := parseClientOptions("up", []string{"1.2.3.4", "demo"})
	if err != nil || helpKind != "" {
		t.Fatalf("unexpected error=%v helpKind=%q", err, helpKind)
	}
	if upOpts.server != "1.2.3.4:8080" || upOpts.room != "demo" {
		t.Fatalf("unexpected target: server=%q room=%q", upOpts.server, upOpts.room)
	}
	if !upOpts.useTun {
		t.Fatalf("expected up mode to enable TUN by default")
	}

	noTunOpts, _, err := parseClientOptions("up", []string{"1.2.3.4:9090", "demo", "--no-tun"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if noTunOpts.useTun {
		t.Fatalf("expected --no-tun to disable TUN in up mode")
	}
	if noTunOpts.server != "1.2.3.4:9090" {
		t.Fatalf("expected port 9090 preserved, got %q", noTunOpts.server)
	}

	meshOpts, _, err := parseClientOptions("mesh", []string{"--server", "10.0.0.1:8080", "--room", "r1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meshOpts.useTun {
		t.Fatalf("expected legacy mesh mode to keep TUN disabled by default")
	}

	meshTunOpts, _, err := parseClientOptions("mesh", []string{"--server", "10.0.0.1:8080", "--room", "r1", "--tun"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !meshTunOpts.useTun {
		t.Fatalf("expected mesh --tun to enable TUN")
	}
}

func TestParseClientOptionsFlagsAfterPositional(t *testing.T) {
	opts, _, err := parseClientOptions("up", []string{
		"1.2.3.4", "team-room",
		"--secret", "s123",
		"-v",
		"--punch-sockets", "128",
		"--stun-list=1.1.1.1:3478,2.2.2.2:3478",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.server != "1.2.3.4:8080" || opts.room != "team-room" {
		t.Fatalf("unexpected server/room: %q / %q", opts.server, opts.room)
	}
	if opts.secret != "s123" || !opts.verbose || opts.punchSockets != 128 {
		t.Fatalf("unexpected flags: secret=%q verbose=%v punchSockets=%d", opts.secret, opts.verbose, opts.punchSockets)
	}
	if opts.stunList != "1.1.1.1:3478,2.2.2.2:3478" {
		t.Fatalf("unexpected stunList=%q", opts.stunList)
	}
	cfg := opts.toSDKConfig()
	if cfg.STUNAddr != "1.2.3.4:8080" || cfg.STUNSecondaries != "1.1.1.1:3478,2.2.2.2:3478" {
		t.Fatalf("unexpected SDK config STUN settings: %+v", cfg)
	}
}

func TestParseClientOptionsP2PURL(t *testing.T) {
	opts, _, err := parseClientOptions("up", []string{
		"p2p://alice:secret42@example.com/lab?token=tok1&tls=1&stun=8.8.8.8:3478",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.server != "example.com:8080" || opts.room != "lab" {
		t.Fatalf("unexpected server/room: %q / %q", opts.server, opts.room)
	}
	if opts.user != "alice" || opts.secret != "secret42" || opts.token != "tok1" {
		t.Fatalf("unexpected auth: user=%q secret=%q token=%q", opts.user, opts.secret, opts.token)
	}
	if !opts.tlsEnable || opts.stunList != "8.8.8.8:3478" {
		t.Fatalf("unexpected tls/stun: tls=%v stun=%q", opts.tlsEnable, opts.stunList)
	}

	roomInUser, _, err := parseClientOptions("up", []string{"p2p://demo@1.2.3.4:8080"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if roomInUser.server != "1.2.3.4:8080" || roomInUser.room != "demo" {
		t.Fatalf("unexpected room-in-user parse: %+v", roomInUser)
	}
}

func TestParseClientOptionsLegacyConnectAndHelp(t *testing.T) {
	// Matches scripts/nat34-check.sh invocation.
	opts, helpKind, err := parseClientOptions("connect", []string{
		"-server", "1.2.3.4:8080",
		"-room", "nat34-probe",
		"-verbose",
		"-stun-list", "1.2.3.4:3479",
		"-sym-spray", "256",
		"-punch-sockets", "256",
	})
	if err != nil || helpKind != "" {
		t.Fatalf("unexpected connect parse failure: err=%v helpKind=%q", err, helpKind)
	}
	if opts.server != "1.2.3.4:8080" || opts.room != "nat34-probe" || !opts.verbose {
		t.Fatalf("unexpected legacy connect opts: %+v", opts)
	}

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--help"}, "help"},
		{[]string{"-h"}, "help"},
		{[]string{"1.2.3.4", "demo", "--help-advanced"}, "help-advanced"},
	} {
		_, got, err := parseClientOptions("up", tc.args)
		if err != nil || got != tc.want {
			t.Fatalf("args=%v got=(%q,%v), want=(%q,nil)", tc.args, got, err, tc.want)
		}
	}

	if _, _, err := parseClientOptions("up", []string{"1.2.3.4"}); err == nil {
		t.Fatalf("expected error when room is missing")
	}
}

func TestEnsurePortAndServerFlagParsing(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":        "1.2.3.4:8080",
		"1.2.3.4:9000":   "1.2.3.4:9000",
		"[::1]:9000":     "[::1]:9000",
		"[::1]":          "[::1]:8080",
		"2001:db8::1":    "[2001:db8::1]:8080",
	}
	for in, want := range cases {
		if got := ensurePort(in, "8080"); got != want {
			t.Fatalf("ensurePort(%q) = %q, want %q", in, got, want)
		}
	}

	if got := parseSTUNServers(" 1.1.1.1:3478 , , 8.8.8.8:3478 "); len(got) != 2 || got[0] != "1.1.1.1:3478" || got[1] != "8.8.8.8:3478" {
		t.Fatalf("unexpected parseSTUNServers result: %v", got)
	}
}
