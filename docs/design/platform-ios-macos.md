# iOS / macOS 接入设计（P5）

> 状态：设计文档。实际实现需要 Apple 开发环境（Xcode、NetworkExtension entitlement）与签名证书，当前仓库未包含可编译的 iOS/macOS 目标。

## 目标

- iOS：通过 `NetworkExtension` 的 `NEPacketTunnelProvider` 建立虚拟网卡，应用通过 `p2p.aar` 的 Go 逻辑（gomobile `-target=ios`）接入 mesh。
- macOS：通过 `UTUN` 接口或 `NetworkExtension` 建立系统级虚拟网卡。

## 建议分层

```text
App (Swift/Kotlin Multiplatform)
        │
        ▼
gomobile 绑定 (Go core)
        │
        ▼
NetworkExtension / UTUN 适配层
        │
        ▼
UDP Internet
```

## 关键点

1. 数据面复用现有 `core/punch`、`core/mesh`、`sdk` 逻辑，平台只提供 TUN 设备适配。
2. iOS 的 `NEPacketTunnelProvider` 需要：
   - 在 `Info.plist` 声明 `NEPacketTunnelNetworkSettings`；
   - 把 mesh socket `protect()` 到隧道外（类似 Android `VpnService.protect`）；
   - 只路由虚拟子网，避免影响正常上网。
3. macOS 可先用 `utun` 字符设备做最小实现，后续再封装为系统扩展。
4. 构建：
   - `gomobile bind -target=ios` 产出 XCFramework；
   - 需要 Apple 开发者证书与 NetworkExtension entitlement。

## 待办

- [ ] 添加 `gomobile bind -target=ios` 构建脚本。
- [ ] 实现 `core/tundev` 的 `darwin` build-tag 适配。
- [ ] 编写 Swift 示例工程。
- [ ] 签名与真机联调。
