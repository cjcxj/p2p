package com.example.p2pdemo

import android.os.Handler
import p2p.Listener
import p2p.P2p
import p2p.Session

/**
 * p2p.Session 的一层薄封装：
 * - 所有 SDK 回调统一切回主线程（SDK 要求回调内不能反调 Session）；
 * - 把 Long 事件码翻译成带类型的回调；
 * - 对外只暴露 demo 需要的 sendToIP / broadcast / 成员列表。
 */
class MeshClient(
    private val mainHandler: Handler,
    private val eventListener: EventListener,
) {
    interface EventListener {
        fun onStateChanged(state: String)
        fun onPeerJoined(virtualIp: String, peerId: String)
        fun onPeerLeft(virtualIp: String, peerId: String)
        fun onPeerConnected(virtualIp: String, transport: String, endpoint: String)
        fun onPeerPathChanged(virtualIp: String, transport: String)
        fun onData(peerIp: String, data: ByteArray)
        fun onError(message: String)
        fun onDebug(message: String)
    }

    data class Peer(
        val virtualIp: String,
        val peerId: String,
        val transport: String,
        val endpoint: String,
        val connected: Boolean,
    )

    private val sdkListener = object : Listener {
        override fun onEvent(event: Long, peerID: String, data: ByteArray) {
            // SDK 文档：OnEvent 内不得回调 Session，统一复制数据后甩到主线程。
            val copy = data.copyOf()
            mainHandler.post { dispatch(event, peerID, copy) }
        }
    }

    @Volatile
    private var session: Session? = null

    val isConnected: Boolean
        get() = session != null

    fun connect(config: MeshConfig) {
        if (session != null) error("已有会话")
        val s = Session(config.toP2p(), sdkListener)
        session = s
        try {
            s.connect(config.room)
        } catch (e: Exception) {
            session = null
            s.disconnect()
            throw e
        }
    }

    fun disconnect() {
        session?.disconnect()
        session = null
    }

    fun localIp(): String? = session?.localIP()?.takeIf { it.isNotEmpty() }

    fun subnet(): String? = session?.subnet()?.takeIf { it.isNotEmpty() }

    fun natType(): String? = session?.natType()?.takeIf { it.isNotEmpty() }

    fun peers(): List<Peer> {
        val s = session ?: return emptyList()
        val count = s.memberCount().toInt()
        if (count <= 0) return emptyList()
        val result = ArrayList<Peer>(count)
        for (i in 0 until count) {
            val member = s.memberAt(i.toLong()) ?: continue
            result.add(
                Peer(
                    virtualIp = member.virtualIP ?: "",
                    peerId = member.peerID ?: "",
                    transport = member.transport ?: "",
                    endpoint = member.endpoint ?: "",
                    connected = member.connected,
                )
            )
        }
        return result
    }

    fun sendToIp(ip: String, data: ByteArray) {
        val s = session ?: error("未连接")
        s.sendToIP(ip, data)
    }

    fun broadcast(data: ByteArray) {
        val s = session ?: error("未连接")
        s.broadcast(data)
    }

    private fun dispatch(event: Long, peerID: String, data: ByteArray) {
        if (event == P2p.EventStateChanged) {
            val state = data.toUtf8()
            // SDK 报告结束状态后，本地引用立即失效，让 UI 允许重新连接。
            if (state == P2p.StateFailed || state == P2p.StateClosed) {
                session = null
            }
            eventListener.onStateChanged(state)
            return
        }
        when (event) {
            P2p.EventPeerJoined -> eventListener.onPeerJoined(peerID, data.toUtf8())
            P2p.EventPeerLeft -> eventListener.onPeerLeft(peerID, data.toUtf8())
            P2p.EventPeerConnected -> {
                val endpoint = session?.let { s ->
                    for (i in 0 until s.memberCount().toInt()) {
                        val m = s.memberAt(i.toLong()) ?: continue
                        if ((m.virtualIP ?: "") == peerID) {
                            return@let m.endpoint ?: ""
                        }
                    }
                    ""
                } ?: ""
                eventListener.onPeerConnected(peerID, data.toUtf8(), endpoint)
            }
            EVENT_PATH_CHANGED -> eventListener.onPeerPathChanged(peerID, data.toUtf8())
            P2p.EventData -> eventListener.onData(peerID, data)
            P2p.EventError -> eventListener.onError(data.toUtf8())
            P2p.EventDebug -> eventListener.onDebug(data.toUtf8())
        }
    }

    private fun ByteArray.toUtf8(): String = String(this, Charsets.UTF_8)

    companion object {
        // app/libs 里的 AAR 还没有 EventPathChanged 常量，按 SDK 协议数值处理。
        private const val EVENT_PATH_CHANGED = 8L
    }
}
