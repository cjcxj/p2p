package p2p

import (
	"testing"

	"p2p/core/protocol"
)

// The observation-point IPs travel in the same string field a signalling server
// that forwards Candidate verbatim will hand back untouched.
func TestCandidatePublicAddrSmuggling(t *testing.T) {
	primary, extras := splitCandidateAddr("223.104.77.212:2501,223.104.77.220,111.206.174.2")
	if primary != "223.104.77.212:2501" {
		t.Fatalf("primary parsed as %q", primary)
	}
	if len(extras) != 2 || extras[0] != "223.104.77.220" || extras[1] != "111.206.174.2" {
		t.Fatalf("extras wrong: %#v", extras)
	}

	// A plain "ip:port" from an old peer must still parse with no extras.
	one, none := splitCandidateAddr("1.2.3.4:5000")
	if one != "1.2.3.4:5000" || none != nil {
		t.Fatalf("single addr split wrong: %q %#v", one, none)
	}
}

func TestCandidateToNATDecodesExtras(t *testing.T) {
	c := &protocol.Candidate{
		NATType:    "symmetric",
		PublicAddr: "223.104.77.212:2501,223.104.77.220",
		PortStep:   0,
	}
	info, err := candidateToNAT(c)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if info.PublicAddr == nil || info.PublicAddr.Port != 2501 || info.PublicAddr.IP.String() != "223.104.77.212" {
		t.Fatalf("primary addr decode wrong: %v", info.PublicAddr)
	}
	if len(info.PublicIPs) != 1 || info.PublicIPs[0].String() != "223.104.77.220" {
		t.Fatalf("observed IP not decoded: %#v", info.PublicIPs)
	}
}
