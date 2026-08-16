# 路线图状态

> 最后更新：v0.22

| 阶段 | 状态 | 说明 |
|---|---|---|
| P0 修复 | ✅ 完成 | K1–K9 已全部修复 |
| P1 数据面安全 | ✅ 完成 | 数据面 AEAD、单播端到端加密（v0.22）、服务器限流、信令 TLS、中继注册加固 |
| P2 链路管理 | ✅ 完成 | keepalive、路径切换事件、静默超时检测、自动重打洞 |
| P3 L7 API | ✅ 完成 | datagram / pub-sub / reliable stream / 连接统计 |
| P4 SDK 分层 | ✅ 完成 | High-Level API（`HighLevel` / `Peer` / `Connection`） |
| P5 平台扩展 | 🟡 部分完成 | systemd/Docker/CLI 脚本、C ABI 头文件、C# 设计、iOS/macOS 设计已完成；C 共享库与 iOS/macOS 原生实现需 Apple/C 编译环境 |
| P6 优化 | ✅ 完成 | 微基准、缓冲池、路由收敛、FEC、双路径择优、批量 IO |
