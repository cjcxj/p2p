// Android 组网示例（Kotlin）
//
// 集成前提：
//   1. 将 android/p2p.aar 作为模块导入（File > New > New Module > Import .AAR）
//   2. app/build.gradle 增加依赖: implementation project(':p2p')
//   3. AndroidManifest.xml 增加:
//        <uses-permission android:name="android.permission.INTERNET"/>
//
// 注意：gomobile 的回调来自 Go 线程，访问 UI 需切换到主线程。

package com.example.p2papp

import android.os.Handler
import android.os.Looper
import androidx.appcompat.app.AppCompatActivity
import p2p.Config
import p2p.Listener
import p2p.P2p
import p2p.Session

class MainActivity : AppCompatActivity() {

    private val mainHandler = Handler(Looper.getMainLooper())
    private lateinit var session: Session
    private var peerIP: String? = null

    fun connect(server: String, room: String, token: String) {
        val cfg = Config()
        cfg.serverAddr = server + ":8080"
        cfg.stunAddr = server + ":8080" // 单端口服务器：STUN 与信令同端口
        cfg.token = token
        cfg.portPrediction = true
        cfg.enableLan = true
        cfg.enableIpv6 = true
        cfg.enableUpnp = true
        cfg.predictionSockets = 96L
        cfg.peerPortOffset = 20L
        cfg.symmetricSpray = 256L

        session = Session(cfg, object : Listener {
            override fun onEvent(event: Long, peerID: String, data: ByteArray) {
                // peerID 在组网模式下是节点的虚拟 IP
                mainHandler.post { handleEvent(event, peerID, data) }
            }
        })
        session.connect(room)
    }

    private fun handleEvent(event: Long, peerID: String, data: ByteArray) {
        when (event) {
            P2p.EventStateChanged -> {
                if (String(data) == P2p.StateConnecting) {
                    statusText.text = "本机虚拟 IP: ${session.localIP()} (${session.subnet()})"
                }
            }
            P2p.EventPeerJoined -> {
                statusText.text = "节点加入: $peerID（共 ${session.memberCount()} 个）"
                for (i in 0 until session.memberCount()) {
                    val m = session.memberAt(i)
                    if (m.virtualIP == peerID) {
                        peerIP = peerID
                    }
                }
            }
            P2p.EventPeerLeft -> {
                if (peerIP == peerID) peerIP = null
            }
            P2p.EventPeerConnected -> {
                // data 为 "punched"
                statusText.text = "已连通 $peerID via ${String(data)}"
            }
            P2p.EventData -> {
                // 组网模式下 peerID 是源虚拟 IP
                val msg = String(data)
                receivedText.append("\n[$peerID] $msg")
            }
            P2p.EventError -> {
                statusText.text = String(data)
            }
        }
    }

    fun sendTo(ip: String, text: String) {
        session.sendToIP(ip, text.toByteArray())
    }

    fun broadcast(text: String) {
        session.broadcast(text.toByteArray())
    }

    fun disconnect() {
        session.disconnect()
    }
}
