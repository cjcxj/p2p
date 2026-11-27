# p2p — 纯直连 P2P WireGuard 组网工具

基于 **单信令服务器 + 多 STUN 观测点 + 全策略 UDP 打洞 + WireGuard 数据面** 的纯直连虚拟局域网 / 网状组网工具。支持同局域网、双栈 IPv6、UPnP/NAT-PMP/PCP 映射以及跨运营商 NAT3（端口受限锥型）↔ NAT4（对称型 / CGNAT）直连打洞，并提供：

- Windows / Linux 统一 CLI（单二进制内置 `server` 与 `up`/`join`/`nat-check`/`mesh`/`connect`，并保留 `p2p-server` / `p2p-client` 兼容入口）
- Android AAR 与 Compose VPN 演示 App（`android/`、`android-demo/`）

## 核心能力

| 能力 | 说明 |
|---|---|
| 纯直连架构 | 单信令服务器（TCP 信令 + 同端口 UDP STUN，可 `--stun-servers` 下发多 STUN 列表），全流量端到端直连打洞 |
| ICE 择优与只升不降 | 按 `LAN > IPv6 > UPnP > Public` 严格分级；低档先通后在升级窗口内继续探测高档候选，命中且稳定即平滑切换，延迟低档回包永不降级 |
| NAT3 ↔ NAT4 穿透 | 支持端口步长（`PortStep`）、端口保持（`PortPreserve`）、BRAS 端口块对齐（`PBA`）、`256` 错峰保活锚点池（`plant`）、**CGNAT 出口块（`CoveringPool`）通告** + 无放回加权生日喷射（热 IP 满窗口，冷 IP 保底 `128`/轮）+ 误判超时自动双端升级 |
| WireGuard 数据面 | 打洞成功后在同一个已打洞 UDP socket 上运行 WireGuard（单包分流发现帧与 WG 帧），支持 IPv4/IPv6 端点与握手包缓存重放 |
| 多跳网状与虚拟网 | 服务器按房间从 `--network`（默认 `10.9.0.0/24`）分配虚拟 IP，支持 OS TUN 虚拟网卡、子网广播仿真与（旧桥接模式）多跳转发 |
| 双向鉴权与加密 | HMAC-SHA256 挑战-应答（`--secret` / `--users`）、可选信令 TLS（`--tls`）、数据面 WireGuard（及传统模式 X25519 + ChaCha20-Poly1305 AEAD） |

## 目录结构

```
sdk/                 Go / gomobile SDK（Session / Config / Listener / Member）
core/
  stun/              STUN 探测 + 多观测点并发枚举 + CGNAT CoveringPool + UPnP/NAT-PMP/PCP
  signaling/         JSON-over-TCP 信令（房间管理、虚拟 IP 分配、多 STUN 下发）
  punch/             纯 P2P 打洞引擎 + ICE 路径分级 + 错峰 plant + 加权无放回喷射
  mesh/              虚拟网络路由、去重/TTL、单播载荷加密
  tundev/            TUN 虚拟网卡与平台防火墙规则（Windows/Linux）
  protocol/          共享 wire 协议
wgengine/            WireGuard 数据面（复用打洞 UDP socket 的 Bind）
cmd/
  p2p/               统一 CLI（server / up / join / nat-check / mesh / connect）
  tput/              隧道吞吐与丢包测试工具
  gencert/           快速生成自签名 TLS 证书
  server/, client/   p2p-server / p2p-client 兼容入口
android/             gomobile 产出的 p2p.aar 与 Kotlin 示例
android-demo/        Android Compose + VpnService 演示工程
scripts/             build.sh / build.ps1 / nat34-check.sh / cloud-symtest.sh / p2p-ctl.sh
```

## 快速开始

### 1. 启动单信令 + STUN 服务器

```bash
# 最简启动（TCP 8080 信令 + UDP 8080 STUN）
p2p server --port 8080

# 推荐：配置多 STUN 服务器列表，自动下发给所有加入客户端（覆盖多运营商 CGNAT 出口枚举）
p2p server --port 8080 --stun-servers stun.miwifi.com:3478,stun.chat.bilibili.com:3478,stun.qq.com:3478

# 开启共享密钥 / 按用户鉴权 / TLS
p2p server --port 8080 --secret <共享密钥>
p2p server --port 8080 --users alice:pass123,bob:pass456 --tls-cert server.crt --tls-key server.key
```

> 常用选项：`--port`（默认 8080）、`--stun-servers`、`--secret`、`--network`（默认 `10.9.0.0/24`）、`--verbose`/`-v`。

### 2. 加入虚拟网络（推荐 `p2p up` / `p2p://`）

`p2p up`（别名 `p2p join`）默认直接开启 WireGuard TUN 虚拟网卡，且参数支持放在位置参数之后：

```bash
# 最简写法（Linux 需 sudo，Windows 需管理员权限 + 同目录 wintun.dll）
sudo p2p up <服务器IP>:8080 demo
sudo p2p up <服务器IP> demo --secret <共享密钥>   # 省略端口默认 :8080

# 也支持 URL 形式（可带账号、密码、token、tls、stun 查询参数）
sudo p2p up "p2p://alice:pass123@<服务器IP>:8080/demo?tls=1&stun=stun.miwifi.com:3478"

# 仅跑文本控制台（不建虚拟网卡）
p2p up <服务器IP>:8080 demo --no-tun
```

旧式命令 `p2p mesh --server ... --room ... --tun`、`p2p connect ...`、`p2p-client ...` 均完全保留兼容。查看参数分层帮助：

```bash
p2p up --help           # 日常高频参数
p2p up --help-advanced  # 底层 NAT4 打洞调参 / TLS / 实验选项
p2p server --help
```

### 3. NAT 与 CGNAT 出口池诊断

```bash
p2p nat-check <服务器IP>:8080 --stun-list stun.miwifi.com:3478,stun.qq.com:3478
```

输出会展示 `NAT type`、本地接口与映射端口、`port step` / `PBA block`、多观测点 `egressIPs` 与 `egressPool`（如 `111.55.212.96/27`）。

### 4. 跨网实测脚本

- `scripts/nat34-check.sh`：两端同时运行测量真实 NAT3↔NAT4 打洞耗时与命中端点。
- `scripts/cloud-symtest.sh`：在独立云主机临时创建 `--random-fully` 对称 NAT 网络命名空间与桌面端真实对打。

## SDK 用法（Go）

```go
package main

import (
	"fmt"
	p2p "p2p/sdk"
)

type app struct{}

func (app) OnEvent(event int, peerID string, data []byte) {
	switch event {
	case p2p.EventPeerConnected:
		fmt.Printf("connected to %s via %s\n", peerID, data)
	case p2p.EventPathChanged:
		fmt.Printf("path upgraded %s -> %s\n", peerID, data)
	case p2p.EventData:
		fmt.Printf("[%s] %s\n", peerID, data)
	}
}

func main() {
	cfg := p2p.Defaults()
	cfg.ServerAddr = "server.example.com:8080"
	cfg.STUNAddr = "server.example.com:8080"
	cfg.STUNSecondaries = "stun.miwifi.com:3478,stun.qq.com:3478"
	cfg.AuthSecret = "共享密钥"

	sess, err := p2p.NewSession(cfg, app{})
	if err != nil {
		panic(err)
	}
	if err := sess.Connect("demo"); err != nil {
		panic(err)
	}
	select {}
}
```

默认参数见 `sdk/config.go`：纯直连模式、`EnableLAN=true`、`EnableIPv6=true`、`EnableUPnP=true`、`PredictionSockets=256`、`SymmetricSpray=512`、`SprayIPMax=64`、`PunchPPS=1500`、`EscalateAfterMs=2000`。

## 构建

```bash
# Linux / macOS（产出 bin/p2p-linux、bin/p2p.exe 及兼容副本，设置 ANDROID_HOME/NDK 时产出 android/p2p.aar）
./scripts/build.sh
```

Windows PowerShell：`scripts\build.ps1`。需要 Go 1.26+。
