package tundev

import (
	"encoding/binary"
	"net"
)

const (
	ipv4ProtocolICMP = 1
	icmpEchoRequest  = 8
	icmpEchoReply    = 0
)

// ipv4Fields returns the source/destination addresses, header length, total
// length, protocol and a validity flag for a raw IPv4 packet.
func ipv4Fields(pkt []byte) (src net.IP, dst net.IP, ihl int, totalLen int, protocol byte, ok bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil, nil, 0, 0, 0, false
	}
	ihl = int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return nil, nil, 0, 0, 0, false
	}
	totalLen = int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen < ihl || totalLen > len(pkt) {
		return nil, nil, 0, 0, 0, false
	}
	src = net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15]).To4()
	dst = net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19]).To4()
	return src, dst, ihl, totalLen, pkt[9], true
}

// IPv4Source extracts the source IPv4 address of a raw IP packet, or nil.
func IPv4Source(pkt []byte) net.IP {
	src, _, _, _, _, ok := ipv4Fields(pkt)
	if !ok {
		return nil
	}
	return src
}

// IsICMPEchoRequest reports whether pkt is an IPv4 ICMP echo request.
func IsICMPEchoRequest(pkt []byte) bool {
	_, _, ihl, totalLen, protocol, ok := ipv4Fields(pkt)
	return ok && protocol == ipv4ProtocolICMP && totalLen >= ihl+8 && pkt[ihl] == icmpEchoRequest
}

// BuildICMPEchoReply turns an IPv4 ICMP echo request into the corresponding
// echo reply. It returns nil when pkt is not a valid IPv4 ICMP echo request.
// The returned slice is exactly the IP packet length (IPv4 header + ICMP).
func BuildICMPEchoReply(pkt []byte) []byte {
	src, dst, ihl, totalLen, protocol, ok := ipv4Fields(pkt)
	if !ok || protocol != ipv4ProtocolICMP || totalLen < ihl+8 || pkt[ihl] != icmpEchoRequest {
		return nil
	}
	reply := append([]byte(nil), pkt[:totalLen]...)

	// Swap source and destination addresses.
	copy(reply[12:16], dst)
	copy(reply[16:20], src)

	// ICMP type: echo request -> echo reply, then recompute ICMP checksum.
	reply[ihl] = icmpEchoReply
	reply[ihl+2] = 0
	reply[ihl+3] = 0
	icmpSum := ipChecksum(reply[ihl:totalLen])
	reply[ihl+2] = byte(icmpSum >> 8)
	reply[ihl+3] = byte(icmpSum)

	// Recompute IPv4 header checksum.
	reply[10] = 0
	reply[11] = 0
	ipSum := ipChecksum(reply[:ihl])
	reply[10] = byte(ipSum >> 8)
	reply[11] = byte(ipSum)

	return reply
}

// ipChecksum implements the RFC 1071 one's complement checksum.
func ipChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
