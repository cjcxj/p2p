# Changelog

## v0.28 (2026-11-27)
- **彻底纯直连化（移除 `core/relay` 中继子系统）**：全面下线服务端与客户端中继代码、`MsgRelayGrant`、`RelayEnabled` 与 `TransportRelay`，单信令服务器仅承担房间信令与 STUN 探测并可下发多 STUN 列表。
- **修复断线重连死锁（上游 `63b4f05`）**：对端重启/重入触发 `AddPeer` 时彻底清零旧连接/端点/tier 状态；`sdk` 改用完整 `wgApplied`（公钥+端点）判定并清理过期 WireGuard peer；`wgengine` 握手重试增加 `peerSpec` 校验防止回写旧路径；补充 `core/punch/rejoin_test.go` 与 `sdk`/`wgengine` 回归测试。
- **修复多节点列表崩溃（上游 `d173698`）**：`Session.memberList()` 按 `PeerID` 确定性排序避免 `MemberAt(i)` 索引错乱，Android `MeshController` 增加 `distinctBy` 去重，修复 2 个以上节点时 `LazyColumn` key 冲突崩溃。
- **Android Demo 3.1 升级（上游 `0827cea`）**：底部导航栏 + 横滑分页、新增 `PeerDetailScreen` 节点详情页、支持 `keystore.properties` 发布签名，同时保留多 STUN 扩展配置与 192/512/1500 调优。

## v0.27 (2026-11-26)
- **纯直连架构 + 单信令多 STUN 下发**：`p2p server --stun-servers` 支持向加入客户端下发多 STUN 观测列表并与客户端 `--stun-list` 合并并发探测。
- **ICE 路径分级与只升不降切换**：按 `LAN > IPv6 > UPnP > Public` 严格定级；低档直连确认后在 `upgradeProbeWindow`（3s）内继续探测更高档候选，命中即平滑升级 WireGuard 端点并触发 `EventPathChanged`，延迟到达的低档包永不覆盖高档路径；修复快速回环/Windows 时钟粒度下的 0ns RTT 边界与 `Seq=0` 保活污染。
- **NAT3 ↔ NAT4 增强与稳态限流**：合并 BRAS PBA 端口块对齐、端口步长/保持预测、`256` 池错峰保活刷新（`round>=2` 每轮只刷批次，避免打爆 CGNAT 配额）、CGNAT `CoveringPool` 加权无放回喷射（热 IP 满 512 窗口优先，冷 IP 保底 128 端口/轮，不饿死未采样出口）、误判超时自动双端升级，并将默认探测速率收敛为 `1500 pps`。
- **CLI 易用性重构**：新增 `p2p up <server[:port]> <room>` / `p2p join`（默认开启 WireGuard TUN，`--no-tun` 退回控制台）及 `p2p://` URL 支持；参数可置于位置参数之后；分层展示 `--help` 常用选项与 `--help-advanced` 底层参数，并保留 `connect`/`mesh`/`p2p-server`/`p2p-client` 100% 向后兼容；打洞/接入日志增加挂钟时间戳。

## v0.26 (2026-11-23)
- **修复 NAT 类型误判**：对称判定要往「第二个目的地」发一次 STUN，代码写的是 `server 端口+1`；而实际部署的信令+STUN+中继只监听一个 UDP 端口（腾讯云安全组也只放行了 8080），那次探测必然无应答，于是**任何 NAT 都被记成 `port_restricted_cone`**——对称 NAT 拿不到 `PortDelta`、也永远不会触发对称策略。现在备选目的地列表为「服务端 port+1 + 公网 STUN（`stun.miwifi.com:3478`、`stun1.l.google.com:19302`）」逐个实测：同一个 socket 在两个目的地拿到不同映射即判 `symmetric` 并测出 delta，拿到同一映射才判 `port_restricted_cone`，全都无应答则新增 `unmeasurable`（不再当作 cone 蒙）。`Detection.Method()` 把判据本身暴露出来，`nat-check` 与 SDK debug 日志都会打印「第二个目的地 X 给出的映射不同/相同」。
- **中继接通后不再终止直连探测**：`probeLoop` 原来只要链路 connected（哪怕是中继）就转 keepalive，直连目标只发一轮（一次突发）就永久停止；而对称 NAT 的映射是按秒轮换的，一轮根本撞不上。现在中继状态下每 1 秒继续扫描直连目标（同时保留中继 keepalive），直连一旦命中就升级为直连；3 分钟仍无直连才认中继。
- **链路只升不降**：`peer.note()` 取代 `classifyTransport()`——已确认的直连端点不会被中继上的 keepalive 覆盖，否则隧道会在直连与中继之间来回摆。
- 疑似对称（`symmetric`/`unmeasurable` 且没有实测 delta）时，端口预测窗口从 4 扩到 12，覆盖 CGNAT 的端口漂移。
- `wgengine.Tunnel.Dump()` 对 `private_key` / `preshared_key` 脱敏：调试日志在手机上会显示在应用自己的日志页里，之前实测泄漏过 WG 私钥。

## v0.25 (2026-11-23)
- **Android Demo 重写（逻辑 + 界面）**：界面换成 Compose + Material 3，分「总览 / 节点 / 工具 / 日志」四页，参数集中在设置面板（含 `legacyMesh` A/B 开关）。
- **一台设备只有一个会话**：会话、节点表、隧道开关统一由进程级 `MeshController` 持有（StateFlow + 事件通道 + 2 秒心跳快照），`MeshVpnService` 不再自建 Session。旧版 Activity 与服务各建一个会话，同一台手机上有两个虚拟 IP 互相打洞，界面显示的链路也不是真正在跑的那条。
- **虚拟网卡与房间解耦**：界面开关只调 `closeTUN()`（会话保持），离开房间才 `disconnect()`；`MeshVpnService` 退化为能力提供者，只注册 `protect(fd)` 与 `Builder().establish()` 两件事到 `VpnBridge`。
- **修正描述符交接 API**：`ParcelFileDescriptor.detachFileDescriptor()` 不是公开 API（编译不过），改用公开的 `detachFd()`；交出后由 Go 关闭，Kotlin 侧不再关。
- **重新 protect 的时机写进流程**：`setSocketProtector` 在虚拟网卡建立之后再调一次——接口一出现默认路由就归 VPN，mesh 的 UDP socket 若不当场摘出隧道，打洞包会绕回自己。
- **连通性自测改为真走隧道**：删掉 `InetAddress.isReachable`（Android 上不保证发 ICMP，且应用 socket 未走隧道会假阴性），改成系统 `/system/bin/ping` 解析 RTT/丢包 + TCP 7000 往返计时；旧的 Kotlin 逐包桥接文件（`MeshClient.kt`、`AppBus.kt`、`MeshConfig.kt`、`activity_main.xml`、`styles.xml`）随之下线。
- 构建：工程离线可编译（`--offline` 用缓存里的 Gradle 9.1.0 与本地已缓存的 Compose 组件；Compose 编译器插件用 `resolutionStrategy.eachPlugin` 直接指到 `compose-compiler-gradle-plugin`，因为插件 marker 不在缓存里）。`:app:assembleDebug` 通过。

## v0.24 (2026-11)
- 数据面换成 WireGuard 隧道：打洞完成后在同一个 UDP socket 上跑 WG，发现帧与隧道帧按首字节分流，IP 流量不再逐包 AEAD + mesh 转发。回环实测每包分配从 6.8 KB/34 次降到 0.3 KB/6 次，1420 字节包吞吐 14–18 万 pkt/s（≈1.6–2.0 Gbit/s），丢包 ≤0.07%。
- 建连不再等 5 秒：WG 的 initiator 由两端 PeerID 排序唯一决定，只有一端发握手；另一端配晚了的坏顺序由 600ms 看门狗重开握手，首包实测从 5.2s 降到 ~1ms（坏顺序 ~0.6s）。
- SDK 新增 `OpenTUN(mtu)` / `TUNName()`（桌面自己创建并配置虚拟网卡）；`AttachTUN(fd, mtu)` 改为把描述符直接交给 WG 接口读写（Android 走 `CreateUnmonitoredTUNFromFD`），不再有逐包桥接。Android 侧的 fd 归 SDK 所有：调用返回后（无论成败）描述符已由 Go 关闭，调用方再关一次会误伤已复用的 fd。
- Android Demo 的 `MeshVpnService` 只剩一次 `attachTUN(pfd.detachFileDescriptor(), mtu)`：删掉 tun 读循环、逐包 IPv4 解析、`sendToIP`/`broadcast` 转发和 ICMP 内核兜底/复探那一整套 Kotlin 桥接（约 200 行），`Ipv4.kt` 随之下线；本机 ICMP 由内核应答，TCP 7000 直接监听即可从虚拟网访问，「用户态协议栈」开关对隧道无效（仅记一条日志）。Android WG 接口的 MTU 由请求值上报（`tundev.fixedMTU`），避免依赖应用可能无权的 `SIOCGIFMTU`。
- CLI `p2p client mesh --tun` 默认走 WG 隧道；新增 `--legacy-mesh`（SDK 为 `Config.LegacyMesh`）退回旧 mesh 网桥，便于真机 A/B 对比与回滚。
- 中继链路暂不进隧道：WG 直接向端点写原始帧，中继只认自己的分帧，因此 relay 节点仍走旧路径；对称 NAT 打不通直连的场景留待后续。

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
