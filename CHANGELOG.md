# Changelog

## v0.27 (2026-11-24)
- **多候选 IP 宽喷不再被 socket 池开关顺带关掉**：`planTargets()` 的「硬对称」分支整体挂在 `PredictionSockets > 1` 上，而 `--punch-sockets 0`（关池）会把这个分支一起跳过——可宽喷那条腿**只用主 socket**，恰恰是打穿「按目的地轮换出口 IP」的 CGNAT 的唯一手段。现在 plant / block / step 对角线这三条池相关的腿各自按池大小门控，宽喷无条件规划。回归用例 `TestPlanTargetsSprayWithoutPool`。
- **对端报了 PortStep 也照样宽喷**：step 对齐的前提是出口 IP 稳定，轮换型 CGNAT 不满足，所以对称对端即使测出 step，step 对角线也只能当**额外一份赌注**，不再作为独占分支把宽喷顶掉（原逻辑 `else if` 就是这个互斥）。反向保护 `TestPlanTargetsConeStepDiagonal`：双方都是 cone 且测出 step 时仍走廉价对角线，不做宽喷。
- **认不出来的 NAT 一律按硬对称处理**：新增 `isHardNAT()`，把 `unknown` / `blocked` 与 `symmetric` / `unmeasurable` 同等对待。之前分类含糊会掉进 cone 快路径，等于**悄悄丢掉了对称 NAT 本来需要的遍历**，最后无声退回中继；现在是失败安全地走激进路径（plant+spray 是 cone 的超集， cone 对端仍会被普通公网目标打通，不亏）。同时删掉 `PortPrediction` 那条单 socket 的 PortDelta 老式扫描分支，池化的 plant+spray 已覆盖。
- **一个 `--stun-list` 条目可以贡献多个观测点**：新增 `stun.ResolveAllUDPAddr()`，把主机名的每条 IPv4 A 记录都当成独立目的地去探测（多宿主 / 负载均衡的公共 STUN 一个条目就能多枚举几个出口），`secondaryAddrs()` 随之去重。IPv4 字面量原样返回、不依赖 DNS（`adb shell` 那类无解析器环境不受影响），解析失败回退单地址解析，只会更好不会更坏。运维含义：与其逼用户抄一堆 IP，不如给一个多 A 记录的域名。
- **`nat-check` 补上同一套能力**：以前只有 `connect` / `mesh` 认 `-stun-list`，现在 `nat-check` 也认，并新增一行 `candidates: [...]` 打印本机在该组观测点下暴露的全部公网出口 IP。调网络时先看这个数字：**candidates 只有 1 个**要么是真 cone（没事），要么是轮换 CGNAT 没被现有 STUN 列表枚举到（需要加观测点）。
- **对称对端只有一个候选 IP 时给可执行提示**：SDK debug 日志会明确说「该对端是 symmetric 但只暴露一个候选出口，若退回中继请为它所在网络加 `--stun-list` 观测点」，把「打不通是玄学」变成有指向性的下一步。
- **真机验证工具**：新增 `scripts/nat34-check.sh`（两台机器各自跑同一个 `--server`/`--room`，逐轮报本机 NAT 类型、是否 `connected via punched`、建连耗时、命中并取胜的对端端点、候选 IP 数；把「某一次侥幸成功」变成 N/N 的成功率账）与 `scripts/cloud-symtest.sh`（在云服务器上用一个临时 netns + `MASQUERADE --random-fully` 造出**真·按目的地轮换端口**的对称 NAT，和家里/公司的 cone 网络跨真实公网做 NAT3↔NAT4，不需要手机）。后者会动共享主机的 netfilter：作用域限定在专用链和 veth 子网，并由 `trap cleanup EXIT` 必回滚，脚本头部写明「先读再跑」。**两个脚本都不落任何管理端点**——SSH 主机与端口只能从参数或 `P2P_SSH` / `P2P_SSH_PORT` 环境变量传入。
- 测试：新增 `core/punch/nat34_test.go`（纯内存 NAT3↔NAT4 模型驱动**真实** Punch 引擎，带负向对照——对端出口 IP 不在候选集内时必须打不通，证明宽喷是真命中了轮换地址，而不是严格过滤被绕过）以及 `ResolveAllUDPAddr` / 候选枚举 / 上述三条策略门控的用例。

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
