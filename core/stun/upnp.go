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

// MapExternalUDP attempts to pin an explicit UDP port mapping on the local
// router/gateway via NAT-PMP (RFC 6886), PCP (RFC 6887), or UPnP IGD within
// budget. It returns the external mapped UDP address if any protocol succeeds,
// or nil when unavailable. Failures are strictly non-fatal.
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

func guessGateway(localIP net.IP) net.IP {
	ip4 := localIP.To4()
	if ip4 == nil || ip4.IsLoopback() || ip4.IsUnspecified() {
		return nil
	}
	// Heuristic: most residential/office /24 gateways sit at x.y.z.1.
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

	// 1. Public address query (v=0, op=0).
	if _, err := c.Write([]byte{0, 0}); err != nil {
		return nil
	}
	buf := make([]byte, 32)
	n, err := c.Read(buf)
	if err != nil || n < 12 || buf[1] != 128 || binary.BigEndian.Uint16(buf[2:4]) != 0 {
		return nil
	}
	extIP := net.IPv4(buf[8], buf[9], buf[10], buf[11])

	// 2. UDP mapping request (v=0, op=1, lifetime=3600s).
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

var (
	reLocation    = regexp.MustCompile(`(?im)^LOCATION:\s*(\S+)`)
	reServiceType = regexp.MustCompile(`(?is)<serviceType>\s*(urn:schemas-upnp-org:service:WAN(?:IP|PPP)Connection:[12])\s*</serviceType>.*?<controlURL>\s*([^<\s]+)\s*</controlURL>`)
	reExtIP       = regexp.MustCompile(`(?is)<NewExternalIPAddress>\s*([^<\s]+)\s*</NewExternalIPAddress>`)
)

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
	ctrlRaw := string(m[2])
	baseURL, err := url.Parse(loc)
	if err != nil {
		return nil
	}
	ctrlRef, err := url.Parse(ctrlRaw)
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
