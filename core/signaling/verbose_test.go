package signaling

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

func TestVerboseMemberLogs(t *testing.T) {
	var buf bytes.Buffer
	srv, err := NewServer("127.0.0.1:0", Options{
		Logger:  log.New(&buf, "", 0),
		Verbose: true,
		Network: "10.9.0.0/24",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	c, err := Dial(srv.Addr().String(), "demo", "", nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if !strings.Contains(buf.String(), "member joined room \"demo\"") {
		t.Fatalf("verbose log missing member joined, got:\n%s", buf.String())
	}

	c.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), "member left room \"demo\"") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("verbose log missing member left, got:\n%s", buf.String())
}
