package stun

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Port-mapping protocols are attempted together because residential gateways
// differ in which one they answer, and each answer is cheap to ask for. PCP
// (RFC 6887) is deliberately absent: a usable MAP request has to carry a nonce
// the gateway handed out first, and in practice these routers answer NAT-PMP or
// IGD, so a hand-rolled nonce-less PCP attempt only spends the budget.

var (
	reLocation    = regexp.MustCompile(`(?im)^LOCATION:\s*(\S+)`)
	reServiceType = regexp.MustCompile(`(?is)<serviceType>\s*(urn:schemas-upnp-org:service:WAN(?:IP|PPP)Connection:[12])\s*</serviceType>.*?<controlURL>\s*([^<\s]+)\s*</controlURL>`)
	reExtIP       = regexp.MustCompile(`(?is)<NewExternalIPAddress>\s*([^<\s]+)\s*</NewExternalIPAddress>`)
)

// MapExternalUDP tries to pin a UDP port mapping on the local gateway through
// NAT-PMP (RFC 6886) and UPnP IGD (SSDP discovery plus AddPortMapping),
// concurrently and within budget. It returns the external address the mapping
// publishes, or nil when no gateway answers. Every failure is non-fatal: a router
// that ignores us must not cost the caller anything beyond the budget.
func MapExternalUDP(localIP net.IP, internalPort int, budget time.Duration) *net.UDPAddr {
	if internalPort <= 0 || internalPort > 65535 {
		return nil
	}
	if budget <= 0 {
		budget = 400 * time.Millisecond
	}
	resCh := make(chan *net.UDPAddr, 2)
	var wg sync.WaitGroup

	if gw := guessGateway(localIP); gw != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if a := mapNATPMP(gw, internalPort, budget); a != nil {
				resCh <- a
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if a := mapUPnP(localIP, internalPort, budget); a != nil {
			resCh <- a
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case addr := <-resCh:
		return addr
	case <-done:
		select {
		case addr := <-resCh:
			return addr
		default:
			return nil
		}
	case <-time.After(budget):
		return nil
	}
}

// guessGateway is the x.y.z.1 heuristic most residential and office gateways use.
// Returning nil when the host itself holds .1 avoids asking a machine to map
// itself.
func guessGateway(localIP net.IP) net.IP {
	ip4 := localIP.To4()
	if ip4 == nil || ip4.IsLoopback() || ip4.IsUnspecified() {
		return nil
	}
	gw := make(net.IP, 4)
	copy(gw, ip4)
	gw[3] = 1
	if gw.Equal(ip4) {
		return nil
	}
	return gw
}

func mapNATPMP(gw net.IP, internalPort int, timeout time.Duration) *net.UDPAddr {
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: gw, Port: 5351})
	if err != nil {
		return nil
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))

	// 1. Public address query (version 0, opcode 0).
	if _, err := c.Write([]byte{0, 0}); err != nil {
		return nil
	}
	buf := make([]byte, 32)
	n, err := c.Read(buf)
	if err != nil || n < 12 || buf[1] != 128 || binary.BigEndian.Uint16(buf[2:4]) != 0 {
		return nil
	}
	extIP := net.IPv4(buf[8], buf[9], buf[10], buf[11])

	// 2. UDP mapping (version 0, opcode 1): suggested internal and external port,
	// then the requested lifetime.
	req := make([]byte, 12)
	req[0] = 0
	req[1] = 1
	binary.BigEndian.PutUint16(req[4:6], uint16(internalPort))
	binary.BigEndian.PutUint16(req[6:8], uint16(internalPort))
	binary.BigEndian.PutUint32(req[8:12], 3600)
	if _, err := c.Write(req); err != nil {
		return nil
	}
	n, err = c.Read(buf)
	if err != nil || n < 16 || buf[1] != 129 || binary.BigEndian.Uint16(buf[2:4]) != 0 {
		return nil
	}
	extPort := int(binary.BigEndian.Uint16(buf[10:12]))
	if extPort <= 0 {
		return nil
	}
	return &net.UDPAddr{IP: extIP, Port: extPort}
}

// mapUPnP discovers an IGD over SSDP, then asks it for a UDP mapping and reads
// the external address back. The dedicated socket is bound to the local LAN
// address so the multicast reaches the gateway's LAN side.
func mapUPnP(localIP net.IP, internalPort int, timeout time.Duration) *net.UDPAddr {
	ip4 := localIP.To4()
	if ip4 == nil || ip4.IsLoopback() || ip4.IsUnspecified() {
		return nil
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip4, Port: 0})
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	mcast := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	for _, st := range []string{
		"urn:schemas-upnp-org:service:WANIPConnection:1",
		"urn:schemas-upnp-org:service:WANPPPConnection:1",
		"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	} {
		msg := fmt.Sprintf("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: %s\r\n\r\n", st)
		_, _ = conn.WriteToUDP([]byte(msg), mcast)
	}

	buf := make([]byte, 4096)
	var loc string
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if m := reLocation.FindSubmatch(buf[:n]); len(m) == 2 {
			loc = strings.TrimSpace(string(m[1]))
			break
		}
	}
	if loc == "" {
		return nil
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(loc)
	if err != nil {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	resp.Body.Close()
	if err != nil {
		return nil
	}
	m := reServiceType.FindSubmatch(body)
	if len(m) != 3 {
		return nil
	}
	svcType := string(m[1])
	baseURL, err := url.Parse(loc)
	if err != nil {
		return nil
	}
	ctrlRef, err := url.Parse(string(m[2]))
	if err != nil {
		return nil
	}
	ctrlURL := baseURL.ResolveReference(ctrlRef).String()

	addBody := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:AddPortMapping xmlns:u="%s">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>%d</NewExternalPort>
      <NewProtocol>UDP</NewProtocol>
      <NewInternalPort>%d</NewInternalPort>
      <NewInternalClient>%s</NewInternalClient>
      <NewEnabled>1</NewEnabled>
      <NewPortMappingDescription>p2p</NewPortMappingDescription>
      <NewLeaseDuration>3600</NewLeaseDuration>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>`, svcType, internalPort, internalPort, ip4.String())
	if !soapCall(client, ctrlURL, svcType+"#AddPortMapping", addBody) {
		return nil
	}

	extBody := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetExternalIPAddress xmlns:u="%s"></u:GetExternalIPAddress>
  </s:Body>
</s:Envelope>`, svcType)
	extResp := soapCallBody(client, ctrlURL, svcType+"#GetExternalIPAddress", extBody)
	if em := reExtIP.FindSubmatch(extResp); len(em) == 2 {
		if ip := net.ParseIP(strings.TrimSpace(string(em[1]))); ip != nil && !ip.IsUnspecified() {
			return &net.UDPAddr{IP: ip, Port: internalPort}
		}
	}
	return nil
}

func soapCall(client *http.Client, urlStr, action, body string) bool {
	req, err := http.NewRequest("POST", urlStr, bytes.NewBufferString(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+action+`"`)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func soapCallBody(client *http.Client, urlStr, action, body string) []byte {
	req, err := http.NewRequest("POST", urlStr, bytes.NewBufferString(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+action+`"`)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	return b
}
