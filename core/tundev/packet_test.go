package tundev

import (
	"net"
	"testing"
)

func TestBuildICMPEchoReply(t *testing.T) {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	pkt[2] = 0
	pkt[3] = 28
	pkt[8] = 64
	pkt[9] = 1 // ICMP
	pkt[12], pkt[13], pkt[14], pkt[15] = 10, 9, 0, 1
	pkt[16], pkt[17], pkt[18], pkt[19] = 10, 9, 0, 2
	pkt[20] = 8 // echo request
	pkt[22] = 0x12
	pkt[23] = 0x34
	pkt[24] = 0x56
	pkt[25] = 0x78

	if !IsICMPEchoRequest(pkt) {
		t.Fatal("expected IsICMPEchoRequest true")
	}

	reply := BuildICMPEchoReply(pkt)
	if reply == nil {
		t.Fatal("BuildICMPEchoReply returned nil")
	}
	if len(reply) != len(pkt) {
		t.Fatalf("reply length = %d, want %d", len(reply), len(pkt))
	}
	if reply[9] != 1 {
		t.Fatalf("protocol = %d, want 1", reply[9])
	}
	if reply[20] != 0 {
		t.Fatalf("ICMP type = %d, want echo reply (0)", reply[20])
	}
	if got := net.IPv4(reply[12], reply[13], reply[14], reply[15]).String(); got != "10.9.0.2" {
		t.Fatalf("reply source = %s, want 10.9.0.2", got)
	}
	if got := net.IPv4(reply[16], reply[17], reply[18], reply[19]).String(); got != "10.9.0.1" {
		t.Fatalf("reply destination = %s, want 10.9.0.1", got)
	}
	if ipChecksum(reply[:20]) != 0 {
		t.Fatalf("IP checksum invalid: %04x", ipChecksum(reply[:20]))
	}
	if ipChecksum(reply[20:]) != 0 {
		t.Fatalf("ICMP checksum invalid: %04x", ipChecksum(reply[20:]))
	}
}

func TestBuildICMPEchoReplyRejectsNonEcho(t *testing.T) {
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	pkt[2] = 0
	pkt[3] = 20
	pkt[9] = 6 // TCP, not ICMP
	if IsICMPEchoRequest(pkt) {
		t.Fatal("TCP packet must not be an ICMP echo request")
	}
	if reply := BuildICMPEchoReply(pkt); reply != nil {
		t.Fatalf("BuildICMPEchoReply on TCP packet returned %d bytes", len(reply))
	}
}
