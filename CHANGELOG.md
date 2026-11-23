# Changelog

## v0.23 (2026-08)
- CLI 客户端与服务端合二为一：新增统一 `cmd/p2p`（`p2p server` / `p2p client ...`，并接受旧式 `p2p mesh/connect/nat-check` 子命令）。
- 构建产物保留 `p2p-server` / `p2p-client` 兼容副本（同一二进制按 `argv[0]` 自动识别角色）。
- 服务器新增 `--verbose`：输出房间创建、成员加入/离开、拒绝原因等详细日志。
- Linux TUN 模式新增 iptables 放行规则：允许虚拟子网经 p2p0 入站/转发的 TCP/UDP/ICMP，修复 Linux 云主机默认防火墙导致 iperf3、TCP 服务无法访问的问题。
- Android Demo 修复自 ping：发给本机虚拟 IP 的 ICMP echo reply 不再丢弃，而是注入 VPN 接口让内核 ping socket 收到。
- netstack 增加 TCP 用户态转发能力（Android 用户态协议栈场景使用），可把入站 TCP 转发到本机 `127.0.0.1:同端口`。
- 桌面 TUN 默认保持内核 TUN；新增 `--userspace-stack` 测试选项，显式开启时才使用用户态协议栈。
- Android Demo 默认改为内核 TUN（“用户态协议栈”默认关闭），与 Windows/Linux 默认行为一致；仍保留开关供测试。
- Android ICMP 改为“内核优先、应用层兜底”：先注入 TUN 等内核回包，超时未回才由应用层代答，并定期复探内核。
- Android Demo 改为 Go 原生 TUN 桥接：TUN 读写直接由 Go SDK 完成，不再每包走 Java/JNI 拷贝，提升 iperf3 吞吐。
- Android Demo 构建时自动把最新 `android/p2p.aar` 同步到 `android-demo/app/libs/p2p.aar`，避免测试用旧 AAR。
- 信令服务器断开时客户端现在会收到 `EventError` 提示（已有 P2P 数据链路保持可用，便于诊断“服务器断开后客户端仍连着”的现象）。

## v0.22 (2026-08)
- 实现单播端到端加密（E2E）：应用载荷在源节点用目的节点密钥加密，中间节点只能路由不能解密。
- 新增 `cmd/gencert` 自签名证书生成工具，简化信令 TLS 启用。
- 新增 `cmd/stress` 本地数据面压测工具（临时信令 + STUN + 双 Session 吞吐测试）。

## v0.21 (2026-08)
- P5：新增 C ABI 头文件、C# P/Invoke 设计、iOS/macOS 接入设计文档。
- 文档：更新 `docs/开发文档.md` 至 v0.21，补全路线图状态。

## v0.20 (2026-08)
- P6：批量 IO。Linux 使用 `ipv4.PacketConn.ReadBatch`，其他平台回退单包读取。

## v0.19 (2026-08)
- P6：双路径择优。直连与中继并行探测，先通先用，后续直连打通自动切换。

## v0.18 (2026-08)
- P6：新增 `core/fec` XOR 前向纠错原语。

## v0.17 (2026-08)
- P6：mesh 反向路由学习，单播优先走已学路由，泛洪降为兜底。

## v0.16 (2026-08)
- P3：L7 新增 `Ping` / `PingStats`，支持 RTT 与丢包率统计。

## v0.15 (2026-08)
- P3：`Member` 新增 `BytesSent` / `BytesReceived` 连接字节统计。

## v0.14 (2026-08)
- P3：新增 L7 API（datagram / pub-sub / reliable ordered stream）。

## v0.13 (2026-08)
- P6：`core/punch` 热路径改用 `sync.Pool` 缓冲复用。

## v0.12 (2026-08)
- P6：新增 `core/punch` / `core/mesh` Encode/Decode benchmarks。

## v0.11 (2026-08)
- P5：新增 Dockerfile、docker-compose、systemd 单元、`scripts/p2p-ctl.sh`。

## v0.10 (2026-08)
- P4：新增 High-Level API（`HighLevel` / `Peer` / `Connection`）。

## v0.9 (2026-08)
- P1：中继注册加固，信令为每个成员签发独立 relay token。

## v0.8 (2026-08)
- P1：信令 TLS 支持（服务器 `--tls-cert/--tls-key`，客户端 `--tls`）。

## v0.7 (2026-08)
- P2：45s 静默超时检测与自动重打洞。

## v0.6 (2026-08)
- P2：新增 `EventPathChanged` 路径切换事件。

## v0.5 (2026-08)
- P1：服务器限流（`--max-conns-per-ip` / `--max-room-members`）。

## v0.4 (2026-08)
- P0/P1：修复 K1/K2/K3/K4/K7/K8；数据面 X25519 + HKDF + ChaCha20-Poly1305 AEAD。

## v0.3 (2026-08)
- 修复 K5/K6/K9；与全量源码对账。

## v0.2 (2026-08)
- 新增质量属性章节、平台支持矩阵。

## v0.1 (2026-08)
- 初稿：架构、模块设计、协议规范、SDK/CLI、构建、路线图。
