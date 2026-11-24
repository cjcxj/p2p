# p2p — 多 NAT 组网工具

基于 STUN + UDP 打洞的 **虚拟局域网 / 网状组网工具**：任意 NAT 环境下的多个节点组成一个
带**虚拟 IP 子网**的私有网络，支持**多跳网状路由**、**广播/组播仿真**，并可创建 **TUN
虚拟网卡**（Windows/Linux）让操作系统流量直接走组网。纯 Go 实现，同一核心同时产出：

- Windows / Linux 的统一 CLI（单个二进制同时包含客户端与三合一服务器，另保留 `p2p-server` / `p2p-client` 兼容入口）
- Android 的 AAR（Java/Kotlin 可直接调用）

## 组网能力

| 能力 | 说明 |
|---|---|
| 虚拟 IP + 子网 | 服务器按房间从 `--network` 子网分配地址（默认 10.9.0.0/24），节点按 IP 寻址 |
| 多跳网状路由 | 无法直连的节点经中间节点转发（泛洪 + TTL + 包去重，任意拓扑可达） |
| 广播/组播仿真 | 子网广播地址与组播范围在虚拟网络内泛洪 |
| NAT 检测 | RFC 3489 行为探测 + 对称端口增量测量 + 多 STUN 观测点枚举公网出口 IP |
| UDP 打洞 | 4 类 NAT 任意组合的策略矩阵 + 对称端口预测 + 多候选出口 IP 宽喷；分类不明一律按对称 NAT 走激进路径 |
| 中继回退 | 类 TURN 房间级中继（房间 token 鉴权），可关闭以强制走对等多跳 |
| 双向鉴权 | HMAC-SHA256 挑战-应答：客户端证明身份给服务器（服务器鉴权），服务器证明身份给客户端（客户端鉴权），防伪服务器/未授权客户端 |
| 数据面加密 | 新客户端间自动协商 X25519 + HKDF + ChaCha20-Poly1305 AEAD；与旧版互通时回退明文 |
| TUN 虚拟网卡 | Windows（wintun.dll）/ Linux（/dev/net/tun）创建网卡，OS 流量直通虚拟网络 |
| WireGuard 数据面 | 打洞成功后在**同一个 UDP socket** 上跑 WireGuard，发现帧与隧道帧按首字节分流；IP 流量不再逐包 AEAD 或用户态转发（`--legacy-mesh` 可回退旧路径做 A/B） |

## 目录结构

```
sdk/                 应用 SDK（Session/Config/Listener/Member，gomobile 可绑定）
core/
  mesh/              虚拟网络层（帧格式、泛洪多跳路由、广播、去重/TTL）
  stun/              STUN 消息编解码 + 服务器 + NAT 分类
  signaling/         JSON-over-TCP 信令（虚拟 IP 分配、成员同步）
  punch/             打洞引擎 + 包格式 + 策略矩阵
  relay/             类 TURN UDP 中继
  tundev/            TUN 虚拟网卡（Windows/Linux）
  protocol/          共享 wire 协议
cmd/
  p2p/                统一 CLI（server / client / nat-check / connect / mesh）
  tput/               隧道吞吐与丢包实测（开发工具，TCP/UDP 双向）
  server/             p2p-server 兼容入口（调用统一 CLI）
  client/             p2p-client 兼容入口（调用统一 CLI）
wgengine/            WireGuard 数据面：隧道设备 + 复用打洞所用 UDP socket 的 bind
android/             gomobile 产出的 p2p.aar + Kotlin 示例
android-demo/        Compose 演示 App（四页界面 + VPN 真接入）
scripts/             build.ps1 / build.sh 一键构建三端 + AAR + wintun.dll；
                     nat34-check.sh / cloud-symtest.sh 真机 NAT3↔NAT4 实测
```

## 快速开始

### 1. 启动服务器（单端口）

信令（TCP）、STUN 与中继（UDP）共用同一个端口号，防火墙只需放行一个端口：

```bash
# 单公网 IP 部署（虚拟网络 10.9.0.0/24）
p2p server --public <公网IP> --port 8080

# 双 IP 部署（可精确区分 full cone；STUN 副 IP 走同端口）
p2p server --public <公网IP> --stun-ip2 <第二IP> --port 8080

# 开启双向鉴权（共享密钥，所有客户端必须携带 --secret）
p2p server --public <公网IP> --port 8080 --secret <共享密钥>

# 开启按用户鉴权（客户端用 --user/--secret 登录）
p2p server --public <公网IP> --port 8080 --users alice:pass123,bob:pass456
```

说明：
- 旧命令 `p2p-server ...` 仍然可用：构建脚本会把统一二进制复制为
  `p2p-server` / `p2p-client`，两者行为与合并前一致。

说明：
- `--port` 同时绑定 TCP（信令）与 UDP（STUN+中继），**默认只占用这一个端口**。
- 可选：`--stun-secondary` 会在 `port+1` 额外绑定一个 STUN 副端口，用于更精确的 NAT
  分类（change-port 测试与对称 NAT 检测）；防火墙需额外放行 `port+1`，不放行也能正常
  工作（退化为保守分类，对称 NAT 走中继/多跳）。不传此参数则服务只监听一个端口。
- 中继地址 = `publicIP:port`，由信令下发给客户端，无需额外端口。

### 2. 组网（控制台模式）

```bash
# 等价写法：p2p client mesh ...（旧命令 p2p-client mesh ... 也继续可用）
# 每个节点运行（--stun 省略时自动与 --server 同端口）
p2p mesh --server <服务器IP>:8080 --room demo --token secret

# 服务器开启鉴权时，客户端需携带凭证
p2p mesh --server <服务器IP>:8080 --room demo --secret <共享密钥>
# 或按用户登录
p2p mesh --server <服务器IP>:8080 --room demo --user alice --secret pass123
```

控制台命令：
- `list` —— 列出节点（虚拟 IP / 传输方式 / peer id）
- `<ip> <msg>` —— 按虚拟 IP 发送（支持多跳）
- `bcast <msg>` —— 向全网广播

### 3. 组网（TUN 虚拟网卡，需管理员/root）

```bash
# Windows：需 wintun.dll 与管理员权限
p2p mesh --server <服务器IP>:8080 --room demo --tun

# Linux：需 root 与 /dev/net/tun
sudo p2p mesh --server <服务器IP>:8080 --room demo --tun

# 测试阶段可选的用户态协议栈（默认关闭；默认全部走内核 TUN）
sudo p2p mesh --server <服务器IP>:8080 --room demo --tun --userspace-stack
```

创建后本机获得虚拟 IP（如 10.9.0.2/24），同一房间内的节点可互相 ping、访问服务。
Windows 的 `wintun.dll` 由构建脚本自动下载到 `bin/`。
Linux 端会自动为虚拟网卡添加 iptables 放行规则（需 root），避免云主机默认防火墙丢弃入站 TCP/UDP。

### 4. 检测本机 NAT

```bash
p2p nat-check --server <服务器IP>:8080

# 带多个 STUN 观测点，枚举本网络暴露的全部公网出口 IP
p2p nat-check --server <服务器IP>:8080 \
    --stun-list stun.miwifi.com:3478,74.125.250.129:19302
```

输出 `NAT type` / `local` / `public` / `candidates` / `port step` / `evidence`（判据本身）。
调网络时先看 `candidates`：只有 1 个地址，要么本机是真 cone（没事），要么是对目的地
轮换出口的 CGNAT 而当前 STUN 列表没枚举到它——后者就要加更多可达的 `--stun-list` 观测点，
否则对称 NAT 那侧的宽喷没有正确的目标 IP 可打，只能退回中继。`--stun-list` 里的主机名
会按 A 记录逐条探测，一个多宿主的公共 STUN 就能贡献多个观测点。

`connect` / `mesh` 用同一个 `--stun-list`（`--punch-sockets`、`--sym-spray`、
`--peer-port-offset` 控制池大小与宽喷宽度），见「NAT 组合与路由」。

## SDK 用法（Go）

```go
import (
	"fmt"
	p2p "p2p/sdk"
)

type app struct{}

func (app) OnEvent(event int, peerID string, data []byte) {
	switch event {
	case p2p.EventPeerConnected:
		fmt.Printf("connected to %s via %s\n", peerID, data) // "punched" / "relay"
	case p2p.EventData:
		fmt.Printf("[%s] %s\n", peerID, data) // peerID 为源虚拟 IP
	}
}

func main() {
	cfg := p2p.Defaults()
	cfg.ServerAddr = "server.example.com:8080"
	cfg.STUNAddr = "server.example.com:8080" // 单端口服务器：STUN 与信令同端口
	cfg.Token = "secret"
	cfg.AuthSecret = "共享密钥" // 服务器开启鉴权时必填；按用户登录时再加 cfg.AuthUser

	sess, err := p2p.NewSession(cfg, app{})
	if err != nil {
		panic(err)
	}
	if err := sess.Connect("demo"); err != nil {
		panic(err)
	}
	fmt.Println("my ip:", sess.LocalIP(), "subnet:", sess.Subnet())

	// 按虚拟 IP 发送（自动多跳）或广播
	// sess.SendToIP("10.9.0.1", []byte("hello"))
	// sess.Broadcast([]byte("hi all"))
	// for _, m := range sess.Members() { fmt.Println(m.VirtualIP, m.Transport, m.Connected) }

	select {}
}
```

事件常量与状态：`EventStateChanged=1` `EventPeerJoined=2` `EventPeerLeft=3`
`EventPeerConnected=4` `EventData=5` `EventError=6`。组网模式下事件的 `peerID` 参数为
**虚拟 IP**。`EventPeerConnected` 的 `data` 为 `punched` 或 `relay`。

SDK 关键 API：

| 方法 | 说明 |
|---|---|
| `LocalIP()` / `Subnet()` | 本机虚拟 IP / 子网 |
| `SendToIP(ip, data)` | 按虚拟 IP 发送（自动多跳） |
| `Broadcast(data)` | 全网广播 |
| `Send(peerIDOrIP, data)` | 按 peer id 或虚拟 IP 发送 |
| `Members()` / `MemberCount()` / `MemberAt(i)` | 节点列表（移动端用后两者） |
| `NATType()` | 本机 NAT 类型 |

配置项见 `sdk/config.go`：`RelayEnabled`（中继回退，默认开；关闭后不可打洞的对端走多跳）、
`PortPrediction`（对称端口预测，默认开）、`EnableLAN`（局域网捷径，默认开）、
`TimeoutSec`、`ProbeIntervalMs`、`PunchTimeoutMs`。

## Android SDK

`android/p2p.aar` 由 `gomobile bind` 生成（含 armeabi-v7a / arm64-v8a / x86 / x86_64）。
完整用法见 `android/example.kt`，要点：

```kotlin
val cfg = Config()
cfg.setServerAddr("server.example.com:8080")
cfg.setSTUNAddr("server.example.com:8080") // 单端口服务器：STUN 与信令同端口
cfg.setToken("secret")

val session = Session(cfg, object : Listener {
    override fun onEvent(event: Long, peerID: String, data: ByteArray) {
        when (event) {
            P2p.EventData -> { /* peerID 为源虚拟 IP */ }
        }
    }
})
session.connect("demo")          // 异步：虚拟 IP 由 localIP() 轮询或等 connected 事件
// session.attachTUN(fd, 1280)   // 把 VpnService 的网卡描述符交给 SDK 跑隧道
// session.closeTUN()            // 只收网卡，房间保持
// session.memberCount(); session.memberAt(i)
// session.disconnect()
```

集成步骤：
1. Android Studio → File → New → New Module → Import .AAR，选择 `p2p.aar`。
2. app 的 `build.gradle` 添加依赖 `implementation project(':p2p')`。
3. `AndroidManifest.xml` 添加 `<uses-permission android:name="android.permission.INTERNET"/>`。

字段 getter 里带连续大写的（`getSTUNAddr`、`getNATType`）请用显式调用而不是 Kotlin 属性语法；
Go 的 `int` 在绑定里是 `long`。

### 安卓 VPN 真接入（demo）

`android-demo` 是 Compose + Material 3 的重写版：**一台设备只有一个会话**。旧版 Activity 和
`MeshVpnService` 各建一个 `Session`，两个虚拟 IP 在同一台手机上互相打洞，界面显示的链路也不是
真正在跑的那条。现在会话、节点表、隧道开关都由进程级 `MeshController` 持有，服务只提供
`protect(fd)` 和虚拟网卡描述符两样 Android 才有的能力。

用法：设置里填服务器与房间 →「接入房间」→ 打开「接入组网虚拟网卡」→ 系统授权后手机拿到
10.9.0.x，**与 Windows/Linux 的 `--tun` 节点互相 ping / 访问服务**：IP 包以 WireGuard 帧在已打洞
的 UDP socket 上收发（`attachTUN(fd, mtu)`，无 Kotlin 逐包桥接），ICMP 由内核应答，本机监听的
TCP 端口（demo 里是 7000）直接从虚拟网可达。VPN 只路由虚拟子网，不影响正常上网；mesh socket 在
网卡建立后会立刻重新 `protect()`，否则打洞包会绕回隧道。

界面分四页：**总览**（本机与参数）、**节点**（VIP + 直连/中继 + UDP 端点 + NAT，点一个设为测试目标）、
**工具**（对目标做 `ping` 与 TCP 7000 往返，走真实隧道）、**日志**（按信息/打洞/隧道/错误过滤）。
虚拟网卡开关只调 `closeTUN()`，房间会话不动；「旧版 mesh 数据面」开关是 A/B 对照，用它比较隧道
与逐包转发的差别。

## NAT 组合与路由

打洞目标由 `core/punch/strategy.go` 统一规划（局域网 → 公网 → 预测端口 → 中继），双方同时
探测。16 种组合全部打通（对称↔对称走中继或对等多跳）。`core/mesh` 在此基础上提供虚拟 IP
寻址与多跳转发：有直连链路则直达，否则泛洪经中间节点，循环由 `(srcIP, pktID)` 去重与
TTL 抑制。

「硬」对端（`symmetric` / `unmeasurable`，以及**分类不明的 `unknown` / `blocked`**——认不出来
就失败安全地按对称处理，不能悄悄走 cone 快路径把对称 NAT 需要的遍历丢掉）走 plant + spray
两条互补角色：

- 本机是硬的那侧：**plant**，把池里每个 socket 都朝对端公布的公网地址发，让自己的映射落到
  对端要打的端口上；
- 本机是 cone 的那侧：**spray**，用主 socket 向对端**每一个候选公网 IP**（服务器看到的 +
  各 STUN 观测点）随机撒 `--sym-spray` 个端口（默认 1024），撞中对称映射的生日攻击。

宽喷只用主 socket，所以 `--punch-sockets 0` 关掉 socket 池**不会**连带关掉它；测出
`port step` 时 step 对角线只是额外一份赌注，不顶掉宽喷（它的前提「出口 IP 稳定」对轮换
CGNAT 不成立）。对端是 symmetric 却只报一个候选出口时，debug 日志会直接提示为该网络加
`--stun-list` 观测点，而不是无声退回中继。

### 真机实测

```bash
# 两台机器（如公司 NAT3 + 手机 CGNAT NAT4）同时跑，同一 server 与 room 前缀：
# 逐轮报本机 NAT 类型、是否 punched、建连耗时、取胜的对端端点、候选 IP 数
bash scripts/nat34-check.sh -s <服务器IP>:8080 -r demo -n 10 \
    --stuns "stun.miwifi.com:3478,74.125.250.129:19302"

# 没有手机时：在云服务器上用临时 netns + MASQUERADE --random-fully 造出真·按目的地
# 轮换端口的对称 NAT，与本机的 cone 网络跨真实公网做 NAT3↔NAT4
P2P_SSH=user@host P2P_SSH_PORT=<端口> bash scripts/cloud-symtest.sh
```

`cloud-symtest.sh` 会修改共享主机的 netfilter（规则作用域限定在专用链与 veth 子网，
`trap` 保证退出时回滚），**先读脚本再运行**。

前提：**造对称 NAT 的那台机器不能同时是信令/STUN 服务器**。命名空间里的客户端一旦把包发往
宿主机自己持有的公网 IP，宿主机按本地投递处理、不从 `eth0` 出，`MASQUERADE -o eth0` 就永远
不触发——测到的是回环路径，没有按目的地换端口，等于没造出对称 NAT（Docker 同理）。所以要
么把信令放在另一台主机（这台脚本只在「SNAT 机 ≠ 服务器机」时给出真结论），要么接回手机当
NAT4 那一侧。两个脚本的管理端点（SSH 主机/端口）只能由参数或环境变量传入，文件里不落任何
凭据与地址。

## 构建

Windows（PowerShell）：

```powershell
scripts\build.ps1
# 产出 bin\p2p.exe、bin\p2p-server.exe、bin\p2p-client.exe、bin\wintun.dll、
#       bin\p2p-linux、bin\p2p-server-linux、bin\p2p-client-linux、android\p2p.aar
# p2p-server / p2p-client 为统一二进制的兼容副本
```

Linux/macOS：

```bash
scripts/build.sh
```

环境要求：Go 1.26+；构建 AAR 需 `gomobile`、`ANDROID_HOME`、`ANDROID_NDK_HOME`
（NDK r27 配 `-androidapi 21`，已写入脚本）。

## 安全说明

- **双向鉴权**：服务器设置 `--secret` 或 `--users` 后，客户端必须携带对应凭证
  （`--secret`，或 `--user`+`--secret`）。握手为 HMAC-SHA256 挑战-应答：服务器验证
  客户端（服务器鉴权），客户端同时验证服务器（客户端鉴权），任一方失败即断开。
- 房间级 `token` 保护房间准入与中继注册，叠加在服务级鉴权之上。
- TUN 模式需管理员/root 权限；请仅加入可信房间。
- 数据通道默认使用 **X25519 + HKDF-SHA256 + ChaCha20-Poly1305** 加密：新版本客户端之间自动协商密钥；与旧版客户端互通时自动回退明文。单播应用载荷额外做**端到端加密**（v0.22），中间节点无法读取应用数据。
- 信令支持可选 **TLS**：服务器 `--tls-cert/--tls-key`，客户端 `--tls`（或 SDK `Config.TLS`）；可用 `go run ./cmd/gencert` 快速生成自签名证书；未启用 TLS 时信令为明文，请勿在不可信网络传输高度敏感凭证。
