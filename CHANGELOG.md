# Changelog

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
