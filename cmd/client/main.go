// Command client is the CLI front end for the P2P SDK.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"p2p/core/stun"
	"p2p/core/tundev"
	p2p "p2p/sdk"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "nat-check":
		os.Exit(runNatCheck(os.Args[2:]))
	case "connect":
		os.Exit(runConnect(os.Args[2:]))
	case "mesh":
		os.Exit(runMesh(os.Args[2:]))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`p2p client

usage:
  p2p nat-check --server <host:port>
  p2p connect --server <host:port> --stun <host:port> --room <id> [options]
  p2p mesh --server <host:port> --stun <host:port> --room <id> [options]

options:
  --token <t>      room secret
  --user <u>       username for server authentication
  --secret <s>     shared secret / password for server authentication
  --no-predict     disable symmetric-NAT port prediction
  --no-relay       disable relay fallback
  --no-lan         disable same-LAN shortcut
  --timeout <sec>  connect timeout
  --verbose        show detailed hole-punching flow logs
  --tls            enable TLS for the signaling connection
  --tls-server-name <n>  TLS ServerName override
  --tls-insecure   skip TLS certificate verification (self-signed only)
  --tun            (mesh) create a TUN device and route OS traffic
  --mtu <n>        (mesh) TUN MTU, default 1280`)
}

func runNatCheck(args []string) int {
	fs := flag.NewFlagSet("nat-check", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:3478", "STUN server address")
	fs.Parse(args)

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		fmt.Println("error:", err)
		return 1
	}
	defer conn.Close()
	addr, err := net.ResolveUDPAddr("udp", *server)
	if err != nil {
		fmt.Println("error:", err)
		return 1
	}
	c := &stun.Client{Conn: conn, Server: addr}
	det, err := c.Detect()
	if err != nil {
		fmt.Println("error:", err)
		return 1
	}
	fmt.Printf("NAT type : %s\n", det.NATType)
	fmt.Printf("local    : %s\n", conn.LocalAddr())
	fmt.Printf("public   : %s\n", det.PublicAddr())
	if det.PortDelta != 0 {
		fmt.Printf("port delta: %d\n", det.PortDelta)
	}
	return 0
}

func runConnect(args []string) int {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:8080", "signaling server address")
	stunAddr := fs.String("stun", "", "STUN server address (default: same host:port as --server)")
	room := fs.String("room", "", "room id")
	token := fs.String("token", "", "room token")
	user := fs.String("user", "", "username for server authentication")
	secret := fs.String("secret", "", "shared secret / password for server authentication")
	noPredict := fs.Bool("no-predict", false, "disable symmetric-NAT port prediction")
	noRelay := fs.Bool("no-relay", false, "disable relay fallback")
	noLAN := fs.Bool("no-lan", false, "disable same-LAN shortcut")
	timeout := fs.Int("timeout", 15, "connect timeout in seconds")
	verbose := fs.Bool("verbose", false, "show detailed hole-punching flow logs")
	tlsEnable := fs.Bool("tls", false, "enable TLS for the signaling connection")
	tlsServerName := fs.String("tls-server-name", "", "TLS ServerName override")
	tlsInsecure := fs.Bool("tls-insecure", false, "skip TLS certificate verification")
	fs.Parse(args)

	if *room == "" {
		fmt.Println("error: --room is required")
		return 2
	}

	cfg := p2p.Defaults()
	cfg.ServerAddr = *server
	if *stunAddr == "" {
		// single-port server: STUN shares the signaling port
		cfg.STUNAddr = *server
	} else {
		cfg.STUNAddr = *stunAddr
	}
	cfg.Token = *token
	cfg.AuthUser = *user
	cfg.AuthSecret = *secret
	cfg.TimeoutSec = *timeout
	cfg.Debug = *verbose
	cfg.TLS = *tlsEnable
	cfg.TLSServerName = *tlsServerName
	cfg.TLSInsecureSkipVerify = *tlsInsecure
	if *noPredict {
		cfg.PortPrediction = false
	}
	if *noRelay {
		cfg.RelayEnabled = false
	}
	if *noLAN {
		cfg.EnableLAN = false
	}

	cli := &cliListener{}
	sess, err := p2p.NewSession(cfg, cli)
	if err != nil {
		fmt.Println("error:", err)
		return 1
	}
	cli.sess = sess

	if err := sess.Connect(*room); err != nil {
		fmt.Println("error:", err)
		return 1
	}
	fmt.Printf("[client] joining room %q\n", *room)

	// stdin -> peer data
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r\n")
			if line == "" {
				continue
			}
			peer := cli.firstPeer()
			if peer == "" {
				fmt.Println("[client] no peer connected yet")
				continue
			}
			if err := sess.Send(peer, []byte(line)); err != nil {
				fmt.Println("[client] send:", err)
			}
		}
	}()

	cli.waitClose()
	return 0
}

// runMesh joins a virtual network; with --tun it creates a TUN device and
// routes OS traffic, otherwise it is an interactive mesh console.
func runMesh(args []string) int {
	fs := flag.NewFlagSet("mesh", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:8080", "signaling server address")
	stunAddr := fs.String("stun", "", "STUN server address (default: same host:port as --server)")
	room := fs.String("room", "", "room id")
	token := fs.String("token", "", "room token")
	user := fs.String("user", "", "username for server authentication")
	secret := fs.String("secret", "", "shared secret / password for server authentication")
	noPredict := fs.Bool("no-predict", false, "disable symmetric-NAT port prediction")
	noRelay := fs.Bool("no-relay", false, "disable relay fallback")
	noLAN := fs.Bool("no-lan", false, "disable same-LAN shortcut")
	timeout := fs.Int("timeout", 15, "connect timeout in seconds")
	useTun := fs.Bool("tun", false, "create a TUN device and route OS traffic")
	mtu := fs.Int("mtu", 1280, "TUN MTU (1280 default: safe across most networks, avoids IP fragmentation)")
	verbose := fs.Bool("verbose", false, "show detailed hole-punching flow logs")
	tlsEnable := fs.Bool("tls", false, "enable TLS for the signaling connection")
	tlsServerName := fs.String("tls-server-name", "", "TLS ServerName override")
	tlsInsecure := fs.Bool("tls-insecure", false, "skip TLS certificate verification")
	fs.Parse(args)

	if *room == "" {
		fmt.Println("error: --room is required")
		return 2
	}

	cfg := p2p.Defaults()
	cfg.ServerAddr = *server
	if *stunAddr == "" {
		cfg.STUNAddr = *server
	} else {
		cfg.STUNAddr = *stunAddr
	}
	cfg.Token = *token
	cfg.AuthUser = *user
	cfg.AuthSecret = *secret
	cfg.TimeoutSec = *timeout
	cfg.Debug = *verbose
	cfg.TLS = *tlsEnable
	cfg.TLSServerName = *tlsServerName
	cfg.TLSInsecureSkipVerify = *tlsInsecure
	if *noPredict {
		cfg.PortPrediction = false
	}
	if *noRelay {
		cfg.RelayEnabled = false
	}
	if *noLAN {
		cfg.EnableLAN = false
	}

	ml := &meshListener{}
	ml.initData()
	sess, err := p2p.NewSession(cfg, ml)
	if err != nil {
		fmt.Println("error:", err)
		return 1
	}
	ml.sess = sess
	if err := sess.Connect(*room); err != nil {
		fmt.Println("error:", err)
		return 1
	}
	fmt.Printf("[mesh] joining room %q\n", *room)

	if *useTun {
		runTun(sess, ml, *mtu)
	} else {
		runMeshConsole(sess, ml)
	}
	return 0
}

// runTun bridges the virtual network with a TUN device.
func runTun(sess *p2p.Session, ml *meshListener, mtu int) {
	ml.mu.Lock()
	ml.tunMode = true
	ml.mu.Unlock()
	// wait for our virtual address
	ip := ml.waitIP()
	if ip == "" {
		fmt.Println("[mesh] no virtual address assigned by server")
		return
	}
	_, ipnet, err := net.ParseCIDR(sess.Subnet())
	if err != nil {
		ipnet = &net.IPNet{IP: net.ParseIP(ip).To4(), Mask: net.CIDRMask(24, 32)}
	}
	dev, err := tundev.Create(net.ParseIP(ip), ipnet.Mask, mtu)
	if err != nil {
		fmt.Println("[mesh] TUN 创建失败:", err)
		fmt.Println("[mesh] 提示: 需要管理员/root 权限；Windows 还需 wintun.dll 放在 exe 同目录")
		return
	}
	defer dev.Close()
	fmt.Printf("[mesh] 虚拟网卡已创建: %s\n", dev.Name())
	// Windows：为虚拟网卡添加防火墙放行规则（ICMP/TCP/UDP/ALL），按虚拟子网
	// 限定 remoteip；否则默认策略会丢弃入站 ICMP（ping 不通的常见原因）
	if err := tundev.AddInterfaceFirewallRules(dev.Name(), ipnet.String()); err != nil {
		fmt.Printf("[mesh] 警告: 添加防火墙放行规则失败: %v\n", err)
		fmt.Printf("[mesh] 提示: 需要管理员权限；ping 不通时请以管理员运行或手动放行\n")
	} else if runtime.GOOS == "windows" {
		fmt.Printf("[mesh] 已为 %s 添加防火墙放行规则（ICMP/TCP/UDP）\n", dev.Name())
	}
	devName := dev.Name()
	defer tundev.RemoveInterfaceFirewallRules(devName)
	// 校验虚拟 IP 是否真的落到了网卡上（排查残留网卡/进程导致的地址混乱）
	realIP := findInterfaceIP(ipnet)
	if realIP == ip {
		fmt.Printf("[mesh] 本机虚拟 IP: %s/%d（%s）\n", ip, maskOnes(ipnet.Mask), sess.Subnet())
	} else if realIP != "" {
		fmt.Printf("[mesh] 注意: 网卡上检测到的 IP 是 %s（不是 %s），可能存在多个旧网卡/进程\n", realIP, ip)
		fmt.Printf("[mesh] 提示: 结束所有 p2p-client 进程后重试；如仍有多个 p2p 网卡请手动删除\n")
	} else {
		fmt.Printf("[mesh] 警告: 未在网卡上检测到 %s，请用 ipconfig 确认虚拟网卡 IP 已配置\n", ip)
	}
	if stale := countInterfacesIn(ipnet); stale > 1 {
		fmt.Printf("[mesh] 警告: 本机有 %d 个网卡使用虚拟子网 %s，建议清理旧的 p2p 网卡\n", stale, ipnet.String())
	}
	fmt.Printf("[mesh] 组网验证: 在另一台已组网的设备上执行 ping %s\n", ip)
	ml.tun = dev

	// 优雅退出：收到 Ctrl+C 时断开并关闭网卡
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		sess.Disconnect()
		dev.Close()
	}()

	// TUN -> mesh
	go func() {
		buf := make([]byte, mtu+256)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			dst := tundev.IPv4Destination(pkt)
			if dst == nil {
				continue
			}
			if tundev.IsBroadcastOrMulticast(dst) {
				if err := sess.Broadcast(pkt); err != nil {
					fmt.Println("[mesh] bcast:", err)
				}
			} else if err := sess.SendToIP(dst.String(), pkt); err != nil {
				fmt.Println("[mesh] send:", err)
			}
		}
	}()

	// mesh -> TUN (ml.data carries IP packets) handled by the listener
	for range ml.data {
	}
}

func maskOnes(m net.IPMask) int {
	ones, _ := m.Size()
	return ones
}

// findInterfaceIP scans local interfaces for an address inside the given
// subnet, returning the first match (the virtual NIC's actual address).
func findInterfaceIP(network *net.IPNet) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && network.Contains(ip) {
				return ip.String()
			}
		}
	}
	return ""
}

// countInterfacesIn counts local interfaces holding an address in the subnet
// (used to detect stale duplicate virtual NICs).
func countInterfacesIn(network *net.IPNet) int {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
	}
	n := 0
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && network.Contains(ip) {
				n++
				break
			}
		}
	}
	return n
}

// runMeshConsole is an interactive virtual-network console.
func runMeshConsole(sess *p2p.Session, ml *meshListener) {
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r\n")
			if line == "" {
				continue
			}
			switch {
			case strings.HasPrefix(line, "bcast "):
				if err := sess.Broadcast([]byte(strings.TrimPrefix(line, "bcast "))); err != nil {
					fmt.Println("[mesh] bcast:", err)
				}
			case strings.HasPrefix(line, "list"):
				for _, m := range sess.Members() {
					state := "down"
					if m.Connected {
						state = m.Transport
					}
					fmt.Printf("  %-16s %s %s\n", m.VirtualIP, state, m.PeerID)
				}
			default:
				parts := strings.SplitN(line, " ", 2)
				if len(parts) == 2 {
					if err := sess.SendToIP(parts[0], []byte(parts[1])); err != nil {
						fmt.Println("[mesh] send:", err)
					}
					continue
				}
				fmt.Println("usage: <ip> <msg> | bcast <msg> | list")
			}
		}
	}()
	for range ml.data {
	}
}

// meshListener prints member/data events and, in TUN mode, routes payloads
// to the TUN device.
type meshListener struct {
	mu      sync.Mutex
	sess    *p2p.Session
	tun     *tundev.Device
	tunMode bool
	data    chan []byte
}

func (m *meshListener) initData() {
	m.mu.Lock()
	if m.data == nil {
		m.data = make(chan []byte, 256)
	}
	m.mu.Unlock()
}

func (m *meshListener) OnEvent(event int, peerID string, data []byte) {
	switch event {
	case p2p.EventStateChanged:
		fmt.Printf("[mesh] state=%s\n", data)
		if string(data) == p2p.StateClosed || string(data) == p2p.StateFailed {
			m.mu.Lock()
			if m.data != nil {
				close(m.data)
				m.data = nil
			}
			m.mu.Unlock()
		}
	case p2p.EventPeerJoined:
		fmt.Printf("[mesh] node joined: %s\n", peerID)
	case p2p.EventPeerLeft:
		fmt.Printf("[mesh] node left: %s\n", peerID)
	case p2p.EventPeerConnected:
		fmt.Printf("[mesh] node connected: %s via %s\n", peerID, data)
		if m.tunMode {
			fmt.Printf("[mesh] 现在可以 ping 该节点: ping %s\n", peerID)
		}
	case p2p.EventData:
		if m.tunMode {
			// TUN 模式：网卡就绪前到达的 IP 包静默丢弃（OS 会重发），
			// 就绪后写入网卡；绝不当作文本打印
			if m.tun != nil {
				m.tun.Write(data)
			}
			return
		}
		fmt.Printf("[mesh] %s: %s\n", peerID, data)
	case p2p.EventError:
		fmt.Printf("[mesh] error: %s\n", data)
	case p2p.EventDebug:
		fmt.Printf("[punch] %s\n", data)
	}
}

func (m *meshListener) waitIP() string {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ip := m.sess.LocalIP(); ip != "" {
			return ip
		}
		time.Sleep(100 * time.Millisecond)
	}
	return m.sess.LocalIP()
}

// cliListener prints events and latches the first connected peer.
type cliListener struct {
	mu    sync.Mutex
	peer  string
	done  chan struct{}
	once  sync.Once
	sess  *p2p.Session
	shown bool
}

func (c *cliListener) firstPeer() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peer
}

func (c *cliListener) waitClose() {
	if c.done == nil {
		select {}
	}
	<-c.done
}

func (c *cliListener) OnEvent(event int, peerID string, data []byte) {
	c.mu.Lock()
	if !c.shown && c.sess != nil {
		if id := c.sess.LocalID(); id != "" && id != "00000000000000000000000000000000" {
			c.shown = true
			fmt.Printf("[client] id=%s\n", id)
		}
	}
	c.mu.Unlock()
	switch event {
	case p2p.EventStateChanged:
		fmt.Printf("[event] state=%s\n", data)
		if string(data) == p2p.StateClosed || string(data) == p2p.StateFailed {
			c.close()
		}
	case p2p.EventPeerJoined:
		fmt.Printf("[event] peer joined: %s\n", peerID)
	case p2p.EventPeerLeft:
		fmt.Printf("[event] peer left: %s\n", peerID)
	case p2p.EventPeerConnected:
		fmt.Printf("[event] peer connected: %s via %s\n", peerID, data)
		c.mu.Lock()
		if c.peer == "" {
			c.peer = peerID
		}
		c.mu.Unlock()
		if c.done == nil {
			c.done = make(chan struct{})
		}
	case p2p.EventData:
		fmt.Printf("[data] %s: %s\n", peerID, data)
	case p2p.EventError:
		fmt.Printf("[error] %s\n", data)
	case p2p.EventDebug:
		fmt.Printf("[punch] %s\n", data)
	}
}

func (c *cliListener) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done != nil {
		select {
		case <-c.done:
		default:
			close(c.done)
		}
	}
}
