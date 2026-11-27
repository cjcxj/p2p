// RunClient is the CLI front end for the P2P SDK.
package cli

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
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

func RunClient(args []string) int {
	if len(args) < 1 {
		ClientUsage()
		return 2
	}
	switch args[0] {
	case "up", "join":
		return runUp(args[1:])
	case "nat-check":
		return runNatCheck(args[1:])
	case "connect":
		return runConnect(args[1:])
	case "mesh":
		return runMesh(args[1:])
	case "--help-advanced":
		ClientAdvancedUsage()
		return 0
	case "-h", "--help", "help":
		ClientUsage()
		return 0
	default:
		ClientUsage()
		return 2
	}
}

func ClientUsage() {
	fmt.Println(`p2p client — pure-P2P direct mesh networking

quickstart:
  p2p up <server[:port]> <room> [options]
  p2p up p2p://<server[:port]>/<room> [options]
  p2p nat-check <server[:port]>

commands:
  up, join   join virtual network with WireGuard TUN enabled (default)
  nat-check  diagnose local NAT type and carrier egress pool
  mesh       virtual network console (--tun optional; legacy compatibility)
  connect    raw probe/text mode (legacy compatibility)

common options:
  --server <host:port>   signaling server (or pass positionally)
  --room <id>            room name (or pass positionally)
  --secret <s>           shared room/server password
  --token <t>            room token (optional)
  --user <u>             username for server authentication
  --stun-list <a,b>      extra comma-separated STUN servers
  --mtu <n>              TUN MTU (default 1280)
  --no-tun               (up) disable OS TUN device and run text console
  --tun                  (mesh) create WireGuard TUN device
  --tls                  enable TLS for signaling
  --timeout <sec>        connect timeout in seconds (default 15)
  --verbose, -v          show detailed punching logs
  --help-advanced        show low-level NAT4 tuning & experimental flags`)
}

func ClientAdvancedUsage() {
	fmt.Println(`p2p client — advanced & experimental options

NAT traversal & STUN tuning:
  --stun <host:port>        primary STUN server (default: --server)
  --punch-sockets <n>       socket pool size for symmetric NAT4 (default 256, 0=off)
  --sym-spray <n>           unique ports sprayed per round by cone peer (default 512)
  --spray-ip-max <n>        max public IPs sprayed per round across CGNAT pool (default 64)
  --punch-pps <n>           outbound probe rate limit in packets/sec (default 1500)
  --escalate-ms <ms>        ms before cone peer escalates to plant+spray (default 2000)
  --peer-port-offset <n>    block spray offset from peer public port (default 20)
  --no-predict              disable symmetric-NAT port prediction
  --no-lan                  disable same-LAN shortcut
  --no-ipv6                 disable dual-stack IPv6 probing
  --no-upnp                 disable UPnP/NAT-PMP/PCP mapping

TLS & experimental:
  --tls-server-name <name>  TLS ServerName override
  --tls-insecure            skip TLS certificate verification (self-signed only)
  --no-encrypt              disable data-plane encryption (both ends must set)
  --legacy-mesh             use retired per-packet mesh bridge instead of WireGuard
  --userspace-stack         (legacy-mesh) forward inbound TCP to 127.0.0.1:same-port`)
}

// ensurePort appends defaultPort if hostPort does not already specify a port.
func ensurePort(hostPort, defaultPort string) string {
	hostPort = strings.TrimSpace(hostPort)
	if hostPort == "" || defaultPort == "" {
		return hostPort
	}
	if _, _, err := net.SplitHostPort(hostPort); err == nil {
		return hostPort
	}
	if strings.Contains(hostPort, ":") && !strings.HasPrefix(hostPort, "[") {
		return "[" + hostPort + "]:" + defaultPort
	}
	return hostPort + ":" + defaultPort
}

// splitFlagsAndPositional splits args into flag tokens (allowing flags after
// positional arguments) and non-flag positional arguments without exiting on help.
func splitFlagsAndPositional(fs *flag.FlagSet, args []string) (flagArgs, positional []string, helpKind string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			name := strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-")
			if name == "h" || name == "help" {
				return nil, nil, "help"
			}
			if name == "help-advanced" {
				return nil, nil, "help-advanced"
			}
			flagArgs = append(flagArgs, a)
			if strings.Contains(name, "=") {
				continue
			}
			if f := fs.Lookup(name); f != nil {
				if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
					continue
				}
				if i+1 < len(args) {
					i++
					flagArgs = append(flagArgs, args[i])
				}
			}
			continue
		}
		positional = append(positional, a)
	}
	return flagArgs, positional, ""
}

type clientOptions struct {
	server         string
	stunAddr       string
	stunList       string
	room           string
	token          string
	user           string
	secret         string
	noPredict      bool
	noLAN          bool
	noIPv6         bool
	noUPnP         bool
	punchSockets   int
	peerPortOffset int
	symSpray       int
	sprayIPMax     int
	punchPPS       int
	escalateMs     int
	noEncrypt      bool
	timeout        int
	useTun         bool
	noTun          bool
	mtu            int
	userspaceStack bool
	legacyMesh     bool
	verbose        bool
	tlsEnable      bool
	tlsServerName  string
	tlsInsecure    bool
}

func parseClientOptions(mode string, args []string) (*clientOptions, string, error) {
	opts := &clientOptions{}
	fs := flag.NewFlagSet(mode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.StringVar(&opts.server, "server", "127.0.0.1:8080", "")
	fs.StringVar(&opts.stunAddr, "stun", "", "")
	fs.StringVar(&opts.stunList, "stun-list", "", "")
	fs.StringVar(&opts.room, "room", "", "")
	fs.StringVar(&opts.token, "token", "", "")
	fs.StringVar(&opts.user, "user", "", "")
	fs.StringVar(&opts.secret, "secret", "", "")
	fs.BoolVar(&opts.noPredict, "no-predict", false, "")
	fs.BoolVar(&opts.noLAN, "no-lan", false, "")
	fs.BoolVar(&opts.noIPv6, "no-ipv6", false, "")
	fs.BoolVar(&opts.noUPnP, "no-upnp", false, "")
	fs.IntVar(&opts.punchSockets, "punch-sockets", 256, "")
	fs.IntVar(&opts.peerPortOffset, "peer-port-offset", 20, "")
	fs.IntVar(&opts.symSpray, "sym-spray", 512, "")
	fs.IntVar(&opts.sprayIPMax, "spray-ip-max", 64, "")
	fs.IntVar(&opts.punchPPS, "punch-pps", 1500, "")
	fs.IntVar(&opts.escalateMs, "escalate-ms", 2000, "")
	fs.BoolVar(&opts.noEncrypt, "no-encrypt", false, "")
	fs.IntVar(&opts.timeout, "timeout", 15, "")
	fs.BoolVar(&opts.verbose, "verbose", false, "")
	fs.BoolVar(&opts.verbose, "v", false, "")
	fs.BoolVar(&opts.tlsEnable, "tls", false, "")
	fs.StringVar(&opts.tlsServerName, "tls-server-name", "", "")
	fs.BoolVar(&opts.tlsInsecure, "tls-insecure", false, "")
	if mode == "up" || mode == "mesh" {
		fs.BoolVar(&opts.useTun, "tun", mode == "up", "")
		fs.BoolVar(&opts.noTun, "no-tun", false, "")
		fs.IntVar(&opts.mtu, "mtu", 1280, "")
		fs.BoolVar(&opts.userspaceStack, "userspace-stack", false, "")
		fs.BoolVar(&opts.legacyMesh, "legacy-mesh", false, "")
	}

	flagArgs, pos, helpKind := splitFlagsAndPositional(fs, args)
	if helpKind != "" {
		return nil, helpKind, nil
	}
	if err := fs.Parse(flagArgs); err != nil {
		return nil, "", err
	}
	setFlags := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })

	if mode == "up" && opts.noTun {
		opts.useTun = false
	}

	if len(pos) > 0 {
		if err := applyPositionalTarget(opts, setFlags, pos); err != nil {
			return nil, "", err
		}
	}
	if opts.room == "" {
		return nil, "", fmt.Errorf("room is required (e.g. `p2p up <server:port> <room>` or `--room <id>`)")
	}
	return opts, "", nil
}

// applyPositionalTarget accepts either:
//   - p2p://[user:secret@|secret@]host[:port]/room[?token=...&tls=1&stun=...]
//   - <server[:port]> [<room>]
func applyPositionalTarget(opts *clientOptions, setFlags map[string]bool, pos []string) error {
	first := strings.TrimSpace(pos[0])
	if strings.HasPrefix(first, "p2p://") {
		u, err := url.Parse(first)
		if err != nil {
			return fmt.Errorf("invalid p2p URL %q: %w", first, err)
		}
		if u.Host == "" {
			return fmt.Errorf("invalid p2p URL %q: missing server host", first)
		}
		if !setFlags["server"] {
			opts.server = ensurePort(u.Host, "8080")
		}
		pathRoom := strings.Trim(u.Path, "/")
		if pathRoom != "" && !setFlags["room"] {
			opts.room = pathRoom
		}
		if u.User != nil {
			uname := u.User.Username()
			pass, hasPass := u.User.Password()
			if hasPass {
				if uname != "" && !setFlags["user"] {
					opts.user = uname
				}
				if pass != "" && !setFlags["secret"] {
					opts.secret = pass
				}
			} else if uname != "" {
				if pathRoom == "" && !setFlags["room"] {
					opts.room = uname
				} else if !setFlags["secret"] {
					opts.secret = uname
				}
			}
		}
		q := u.Query()
		if tok := q.Get("token"); tok != "" && !setFlags["token"] {
			opts.token = tok
		}
		if stun := q.Get("stun"); stun != "" && !setFlags["stun-list"] {
			opts.stunList = stun
		}
		if tlsVal := q.Get("tls"); (tlsVal == "1" || strings.EqualFold(tlsVal, "true")) && !setFlags["tls"] {
			opts.tlsEnable = true
		}
		if len(pos) > 1 && !setFlags["room"] && opts.room == "" {
			opts.room = pos[1]
		}
		return nil
	}

	if !setFlags["server"] {
		opts.server = ensurePort(first, "8080")
	}
	if len(pos) > 1 && !setFlags["room"] {
		opts.room = pos[1]
	}
	return nil
}

func (o *clientOptions) toSDKConfig() *p2p.Config {
	cfg := p2p.Defaults()
	cfg.ServerAddr = o.server
	if o.stunAddr == "" {
		cfg.STUNAddr = o.server
	} else {
		cfg.STUNAddr = o.stunAddr
	}
	cfg.Token = o.token
	cfg.AuthUser = o.user
	cfg.AuthSecret = o.secret
	cfg.TimeoutSec = o.timeout
	cfg.Debug = o.verbose
	cfg.TLS = o.tlsEnable
	cfg.TLSServerName = o.tlsServerName
	cfg.TLSInsecureSkipVerify = o.tlsInsecure
	cfg.Plaintext = o.noEncrypt
	if o.noPredict {
		cfg.PortPrediction = false
	}
	if o.noLAN {
		cfg.EnableLAN = false
	}
	if o.noIPv6 {
		cfg.EnableIPv6 = false
	}
	if o.noUPnP {
		cfg.EnableUPnP = false
	}
	cfg.PredictionSockets = o.punchSockets
	cfg.PeerPortOffset = o.peerPortOffset
	cfg.SymmetricSpray = o.symSpray
	cfg.SprayIPMax = o.sprayIPMax
	cfg.PunchPPS = o.punchPPS
	cfg.EscalateAfterMs = o.escalateMs
	cfg.STUNSecondaries = o.stunList
	cfg.LegacyMesh = o.legacyMesh
	return cfg
}

func runNatCheck(args []string) int {
	fs := flag.NewFlagSet("nat-check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	server := fs.String("server", "127.0.0.1:3478", "STUN server address")
	stunList := fs.String("stun-list", "", "comma-separated extra STUN observation points")

	flagArgs, pos, helpKind := splitFlagsAndPositional(fs, args)
	if helpKind == "help-advanced" {
		ClientAdvancedUsage()
		return 0
	}
	if helpKind == "help" {
		fmt.Println("usage: p2p nat-check [<server[:port]>] [--server <host:port>] [--stun-list <a,b>]")
		return 0
	}
	if err := fs.Parse(flagArgs); err != nil {
		fmt.Println("error:", err)
		return 2
	}
	serverExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "server" {
			serverExplicit = true
		}
	})
	if len(pos) > 0 && !serverExplicit {
		*server = ensurePort(pos[0], "8080")
	}

	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		fmt.Println("error:", err)
		return 1
	}
	defer conn.Close()
	addr, err := net.ResolveUDPAddr("udp4", *server)
	if err != nil {
		fmt.Println("error:", err)
		return 1
	}
	var secs []string
	for _, s := range strings.Split(*stunList, ",") {
		if s = strings.TrimSpace(s); s != "" {
			secs = append(secs, s)
		}
	}
	c := &stun.Client{
		Conn:             conn,
		Server:           addr,
		SecondaryTimeout: 800 * time.Millisecond,
		StepSamples:      stun.DefaultStepSamples,
		Secondaries:      secs,
	}
	det, err := c.Detect()
	if err != nil {
		fmt.Println("error:", err)
		return 1
	}
	fmt.Printf("NAT type : %s\n", det.NATType)
	fmt.Printf("local    : %s\n", conn.LocalAddr())
	fmt.Printf("public   : %s\n", det.PublicAddr())
	if det.PortPreserve {
		fmt.Printf("preserve : true (offset %+d)\n", det.PortPreserveOffset)
	}
	if det.PortStep != 0 {
		fmt.Printf("port step: %d\n", det.PortStep)
	}
	if det.PortBlockMin > 0 {
		fmt.Printf("PBA block: %d..%d\n", det.PortBlockMin, det.PortBlockMax)
	}
	if len(det.ObservedIPs) > 1 {
		fmt.Printf("egressIPs: %v\n", det.ObservedIPs)
	}
	if pool := det.CoveringPool(); pool != nil {
		fmt.Printf("egressPool: %s\n", pool)
	}
	if m := det.Method(); m != "" {
		fmt.Printf("evidence : %s\n", m)
	}
	return 0
}

func runConnect(args []string) int {
	opts, helpKind, err := parseClientOptions("connect", args)
	if helpKind == "help-advanced" {
		ClientAdvancedUsage()
		return 0
	}
	if helpKind == "help" {
		ClientUsage()
		return 0
	}
	if err != nil {
		fmt.Println("error:", err)
		return 2
	}

	cli := &cliListener{}
	sess, err := p2p.NewSession(opts.toSDKConfig(), cli)
	if err != nil {
		fmt.Println("error:", err)
		return 1
	}
	cli.sess = sess

	if err := sess.Connect(opts.room); err != nil {
		fmt.Println("error:", err)
		return 1
	}
	fmt.Printf("[client] joining room %q (server=%s)\n", opts.room, opts.server)

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

func runUp(args []string) int {
	return runMeshMode("up", args)
}

// runMesh joins a virtual network; with --tun it creates a TUN device and
// routes OS traffic, otherwise it is an interactive mesh console.
func runMesh(args []string) int {
	return runMeshMode("mesh", args)
}

func runMeshMode(mode string, args []string) int {
	opts, helpKind, err := parseClientOptions(mode, args)
	if helpKind == "help-advanced" {
		ClientAdvancedUsage()
		return 0
	}
	if helpKind == "help" {
		ClientUsage()
		return 0
	}
	if err != nil {
		fmt.Println("error:", err)
		return 2
	}

	ml := &meshListener{}
	ml.initData()
	sess, err := p2p.NewSession(opts.toSDKConfig(), ml)
	if err != nil {
		fmt.Println("error:", err)
		return 1
	}
	ml.sess = sess
	if err := sess.Connect(opts.room); err != nil {
		fmt.Println("error:", err)
		return 1
	}
	fmt.Printf("[mesh] joining room %q (server=%s)\n", opts.room, opts.server)

	if opts.useTun {
		runTun(sess, ml, opts.mtu, opts.userspaceStack, opts.legacyMesh)
	} else {
		runMeshConsole(sess, ml)
	}
	return 0
}

// runTun bridges the virtual network with a TUN device. The default data plane
// is a WireGuard tunnel on the hole-punched UDP socket; --legacy-mesh puts the
// retired per-packet bridge back so the two can be compared on one machine.
func runTun(sess *p2p.Session, ml *meshListener, mtu int, userspaceStack, legacyMesh bool) {
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
	if !legacyMesh {
		runWGTunnel(sess, ml, ip, ipnet, mtu)
		return
	}
	if userspaceStack {
		if err := sess.EnableLocalStack(); err != nil {
			fmt.Printf("[mesh] 警告: 用户态协议栈启用失败，继续使用内核 TUN: %v\n", err)
		} else {
			fmt.Printf("[mesh] 用户态协议栈已启用（测试选项，入站 TCP 转发到 127.0.0.1:同端口）\n")
		}
	}
	dev, err := tundev.Create(net.ParseIP(ip), ipnet.Mask, mtu)
	if err != nil {
		fmt.Println("[mesh] TUN 创建失败:", err)
		fmt.Println("[mesh] 提示: 需要管理员/root 权限；Windows 还需 wintun.dll 放在 exe 同目录")
		return
	}
	defer dev.Close()
	fmt.Printf("[mesh] 虚拟网卡已创建: %s\n", dev.Name())
	addTunFirewallRules(dev.Name(), ipnet)
	defer tundev.RemoveInterfaceFirewallRules(dev.Name())
	reportTunAddress(ip, ipnet, sess)
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

// runWGTunnel starts the SDK's WireGuard tunnel and stays alive until Ctrl+C.
// The interface, its address and every packet on it belong to the session;
// this only reports on the result and opens the firewall for the new NIC.
func runWGTunnel(sess *p2p.Session, ml *meshListener, ip string, ipnet *net.IPNet, mtu int) {
	if err := sess.OpenTUN(mtu); err != nil {
		fmt.Println("[mesh] WireGuard 隧道启动失败:", err)
		fmt.Println("[mesh] 提示: 需要管理员/root 权限；Windows 还需 wintun.dll 放在 exe 同目录")
		fmt.Println("[mesh] 提示: 可临时加 --legacy-mesh 走旧网桥对比")
		return
	}
	name := sess.TUNName()
	fmt.Printf("[mesh] WireGuard 隧道已启动（虚拟网卡 %s）\n", name)
	addTunFirewallRules(name, ipnet)
	defer tundev.RemoveInterfaceFirewallRules(name)
	reportTunAddress(ip, ipnet, sess)
	fmt.Printf("[mesh] 组网验证: 在另一台已组网的设备上执行 ping %s\n", ip)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		sess.Disconnect()
	}()
	for range ml.data {
	}
}

// addTunFirewallRules 为虚拟网卡添加防火墙放行规则（ICMP/TCP/UDP/ALL），按
// 虚拟子网限定 remoteip；否则默认策略会丢弃入站 ICMP（ping 不通的常见原因）。
func addTunFirewallRules(name string, ipnet *net.IPNet) {
	if err := tundev.AddInterfaceFirewallRules(name, ipnet.String()); err != nil {
		fmt.Printf("[mesh] 警告: 添加防火墙放行规则失败: %v\n", err)
		if runtime.GOOS == "windows" {
			fmt.Printf("[mesh] 提示: 需要管理员权限；ping 不通时请以管理员运行或手动放行\n")
		} else {
			fmt.Printf("[mesh] 提示: Linux 请以 root 运行并确保 iptables 可用；若使用 nftables，请手动放行 %s 的虚拟子网入站流量\n", name)
		}
	} else if runtime.GOOS == "windows" {
		fmt.Printf("[mesh] 已为 %s 添加防火墙放行规则（ICMP/TCP/UDP）\n", name)
	} else {
		fmt.Printf("[mesh] 已为 %s 添加 iptables 放行规则（虚拟子网 TCP/UDP/ICMP）\n", name)
	}
}

// reportTunAddress 校验虚拟 IP 是否真的落到了网卡上（排查残留网卡/进程导致的
// 地址混乱）。
func reportTunAddress(ip string, ipnet *net.IPNet, sess *p2p.Session) {
	realIP := findInterfaceIP(ipnet)
	if realIP == ip {
		fmt.Printf("[mesh] 本机虚拟 IP: %s/%d（%s）\n", ip, maskOnes(ipnet.Mask), sess.Subnet())
	} else if realIP != "" {
		fmt.Printf("[mesh] 注意: 网卡上检测到的 IP 是 %s（不是 %s），可能存在多个旧网卡/进程\n", realIP, ip)
		fmt.Printf("[mesh] 提示: 结束所有 p2p / p2p-client 进程后重试；如仍有多个 p2p 网卡请手动删除\n")
	} else {
		fmt.Printf("[mesh] 警告: 未在网卡上检测到 %s，请用 ipconfig 确认虚拟网卡 IP 已配置\n", ip)
	}
	if stale := countInterfacesIn(ipnet); stale > 1 {
		fmt.Printf("[mesh] 警告: 本机有 %d 个网卡使用虚拟子网 %s，建议清理旧的 p2p 网卡\n", stale, ipnet.String())
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
					if m.Connected && m.Endpoint != "" {
						fmt.Printf("  %-16s %-8s %s (%s)\n", m.VirtualIP, state, m.PeerID, m.Endpoint)
					} else {
						fmt.Printf("  %-16s %s %s\n", m.VirtualIP, state, m.PeerID)
					}
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
		endpoint := ""
		if m.sess != nil {
			for _, mem := range m.sess.Members() {
				if mem.VirtualIP == peerID && mem.Endpoint != "" {
					endpoint = mem.Endpoint
					break
				}
			}
		}
		if endpoint != "" {
			fmt.Printf("[mesh] %s node connected: %s via %s (%s)\n", ts(), peerID, data, endpoint)
		} else {
			fmt.Printf("[mesh] %s node connected: %s via %s\n", ts(), peerID, data)
		}
		if m.tunMode {
			fmt.Printf("[mesh] 现在可以 ping 该节点: ping %s\n", peerID)
		}
	case p2p.EventPathChanged:
		endpoint := ""
		if m.sess != nil {
			for _, mem := range m.sess.Members() {
				if mem.VirtualIP == peerID && mem.Endpoint != "" {
					endpoint = mem.Endpoint
					break
				}
			}
		}
		if endpoint != "" {
			fmt.Printf("[mesh] %s path upgraded: %s -> %s (%s)\n", ts(), peerID, data, endpoint)
		} else {
			fmt.Printf("[mesh] %s path upgraded: %s -> %s\n", ts(), peerID, data)
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
		fmt.Printf("[punch] %s %s\n", ts(), data)
	}
}

// ts stamps pacing-sensitive lines with a wall clock so round counters show
// elapsed seconds directly in console logs.
func ts() string { return time.Now().Format("15:04:05") }

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
	case p2p.EventPathChanged:
		fmt.Printf("[event] path upgraded: %s -> %s\n", peerID, data)
	case p2p.EventData:
		fmt.Printf("[data] %s: %s\n", peerID, data)
	case p2p.EventError:
		fmt.Printf("[error] %s\n", data)
	case p2p.EventDebug:
		fmt.Printf("[punch] %s %s\n", ts(), data)
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
