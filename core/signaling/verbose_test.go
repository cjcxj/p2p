package signaling

import (
	"log"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is the log sink for this test. The server writes it from its own
// goroutines while the test polls for the lines it produces, so an unguarded
// bytes.Buffer here is a data race the race detector reports -- the log, not the
// server, was what raced.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// contains waits for the server's log line rather than assuming it has already
// been written: under the race detector, with the machine loaded, the announcing
// goroutine routinely loses to the test.
func (b *syncBuffer) contains(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(b.String(), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("verbose log missing %q, got:\n%s", want, b.String())
}

func TestVerboseMemberLogs(t *testing.T) {
	buf := &syncBuffer{}
	srv, err := NewServer("127.0.0.1:0", Options{
		Logger:  log.New(buf, "", 0),
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
	buf.contains(t, `member joined room "demo"`)

	c.Close()
	buf.contains(t, `member left room "demo"`)
}
