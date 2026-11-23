package com.example.p2pdemo

import p2p.Config

/**
 * 与 UI 无关的连接参数。MainActivity 和 MeshVpnService 共用同一套构造逻辑，
 * 避免两处各写一遍 Config。
 */
data class MeshConfig(
    val serverAddr: String,
    val room: String,
    val token: String = "",
    val authUser: String = "",
    val authSecret: String = "",
    val relayEnabled: Boolean = true,
    val portPrediction: Boolean = true,
    val enableLan: Boolean = true,
    val debug: Boolean = false,
    val plaintext: Boolean = false,
) {
    fun toP2p(): Config {
        val cfg = Config()
        cfg.serverAddr = serverAddr
        // 单端口服务器：信令 / STUN / 中继共用同一地址和端口。
        cfg.stunAddr = serverAddr
        cfg.token = token
        cfg.authUser = authUser
        cfg.authSecret = authSecret
        cfg.relayEnabled = relayEnabled
        cfg.portPrediction = portPrediction
        cfg.enableLAN = enableLan
        cfg.debug = debug
        cfg.plaintext = plaintext
        return cfg
    }
}

/**
 * 启动 MeshVpnService 所需的参数，通过 Intent extras 传递。
 */
data class VpnRequest(
    val server: String,
    val room: String,
    val token: String = "",
    val authUser: String = "",
    val authSecret: String = "",
    val localStack: Boolean = false,
    val relayEnabled: Boolean = true,
    val debug: Boolean = true,
    val plaintext: Boolean = false,
) {
    fun toMeshConfig(): MeshConfig = MeshConfig(
        serverAddr = server,
        room = room,
        token = token,
        authUser = authUser,
        authSecret = authSecret,
        relayEnabled = relayEnabled,
        portPrediction = true,
        enableLan = true,
        debug = debug,
        plaintext = plaintext,
    )
}
