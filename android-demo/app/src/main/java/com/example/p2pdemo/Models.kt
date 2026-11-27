package com.example.p2pdemo

import p2p.Config
import p2p.P2p

/**
 * 入房所需的全部参数。设置面板、控制器和 VPN 服务共用同一份定义，
 * 避免以前“UI 一套、服务再拼一套”的重复。
 */
data class ConnConfig(
    val serverAddr: String = "",
    val room: String = "",
    val token: String = "",
    val authUser: String = "",
    val authSecret: String = "",
    val stunList: String = "",
    val debug: Boolean = true,
    val plaintext: Boolean = false,
    val legacyMesh: Boolean = false,
) {
    val isValid: Boolean
        get() = serverAddr.isNotBlank() && room.isNotBlank()

    fun toP2p(): Config {
        val cfg = Config()
        cfg.setServerAddr(serverAddr)
        // 单信令服务器（可选同端口主 STUN），同时支持信令下发与本地扩展多 STUN。
        cfg.setSTUNAddr(serverAddr)
        cfg.setSTUNSecondaries(stunList)
        cfg.setToken(token)
        cfg.setAuthUser(authUser)
        cfg.setAuthSecret(authSecret)
        cfg.setPortPrediction(true)
        cfg.setEnableLAN(true)
        cfg.setEnableIPv6(true)
        cfg.setEnableUPnP(true)
        // NAT3<->NAT4 并行探测 + 192 错峰保活锚点池 + 512 加权无放回随机喷射 + 1500 PPS 限速。
        cfg.setPredictionSockets(192L)
        cfg.setPeerPortOffset(20L)
        cfg.setSymmetricSpray(512L)
        cfg.setSprayIPMax(64L)
        cfg.setProbeIntervalMs(60L)
        cfg.setPunchPPS(1500L)
        cfg.setEscalateAfterMs(2000L)
        cfg.setDebug(debug)
        cfg.setPlaintext(plaintext)
        cfg.setLegacyMesh(legacyMesh)
        return cfg
    }
}

/** 会话阶段：UI 只显示这五种，SDK 的字符串状态在控制器里翻译。 */
enum class SessionPhase { Idle, Connecting, Connected, Closed, Failed }

fun sessionPhaseOf(state: String): SessionPhase = when (state) {
    P2p.StateConnecting -> SessionPhase.Connecting
    P2p.StateConnected -> SessionPhase.Connected
    P2p.StateClosed -> SessionPhase.Closed
    P2p.StateFailed -> SessionPhase.Failed
    else -> SessionPhase.Idle
}

/** 虚拟网卡阶段。Starting 让开关在建立期间显示等待而不是假成功。 */
enum class TunnelPhase { Off, Starting, On }

/** 一个节点的展示行，字段直接来自 SDK 的 Member 快照。 */
data class PeerRow(
    val virtualIp: String,
    val peerId: String,
    val transport: String,
    val endpoint: String,
    val natType: String,
    val connected: Boolean,
) {
    val isDirect: Boolean
        get() = transport == P2p.TransportPunched

    val linkLabel: String
        get() = when {
            !connected -> "未连通"
            isDirect -> "直连"
            else -> transport
        }
}

enum class LogKind { Info, Punch, Error, Tunnel }

data class LogLine(val at: Long, val kind: LogKind, val text: String)

enum class TestKind { Ping, Echo }

/** 连通性自测的一次结果。running 让按钮在等待期间显示进行中而不是假成功。 */
data class TestRun(
    val kind: TestKind = TestKind.Ping,
    val target: String = "",
    val running: Boolean = false,
    val ok: Boolean? = null,
    val summary: String = "",
)

/** UI 的唯一数据源。 */
data class MeshUiState(
    val phase: SessionPhase = SessionPhase.Idle,
    val busy: Boolean = false,
    val localId: String = "",
    val localIp: String = "",
    val subnet: String = "",
    val natType: String = "",
    val peers: List<PeerRow> = emptyList(),
    val tunnel: TunnelPhase = TunnelPhase.Off,
    val tunName: String = "",
    val error: String = "",
    val config: ConnConfig = ConnConfig(),
    val targetIp: String = "",
    val test: TestRun = TestRun(),
) {
    val hasSession: Boolean
        get() = phase == SessionPhase.Connecting || phase == SessionPhase.Connected

    val directPeers: Int
        get() = peers.count { it.isDirect }
}
