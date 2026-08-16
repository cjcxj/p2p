package com.example.p2pdemo

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.TextView
import p2p.Config
import p2p.Listener
import p2p.P2p
import p2p.Session

class MainActivity : Activity() {

    private val ui = Handler(Looper.getMainLooper())
    private var session: Session? = null
    private var vpnRunning = false

    private lateinit var serverInput: EditText
    private lateinit var roomInput: EditText
    private lateinit var tokenInput: EditText
    private lateinit var userInput: EditText
    private lateinit var secretInput: EditText
    private lateinit var statusText: TextView
    private lateinit var memberText: TextView
    private lateinit var logText: TextView
    private lateinit var peerInput: EditText
    private lateinit var msgInput: EditText

    private val listener = object : Listener {
        override fun onEvent(event: Long, peerID: String, data: ByteArray) {
            ui.post { handleEvent(event, peerID, data) }
        }
    }

    // 入站 TCP 回显服务：Windows 连 手机虚拟IP:7000 即可测试入站 TCP 是否真的可达
    private var echoServer: java.net.ServerSocket? = null

    private fun startEchoServer() {
        try {
            val srv = java.net.ServerSocket()
            srv.reuseAddress = true
            srv.bind(java.net.InetSocketAddress(7000))
            echoServer = srv
            appendLog("TCP 回显服务已启动: 端口 7000")
            Thread {
                while (true) {
                    val c = try { srv.accept() } catch (e: Exception) { break }
                    appendLog("TCP 收到连接: ${c.inetAddress.hostAddress}")
                    Thread {
                        try {
                            val buf = ByteArray(4096)
                            while (true) {
                                val n = c.inputStream.read(buf)
                                if (n <= 0) break
                                c.outputStream.write(buf, 0, n)
                                c.outputStream.flush()
                            }
                        } catch (e: Exception) { }
                        try { c.close() } catch (e: Exception) { }
                    }.start()
                }
            }.start()
        } catch (e: Exception) {
            appendLog("TCP 回显启动失败: ${e.message}")
        }
    }

    // 自测 ping：App 经 VPN 向外发 ICMP（测试出站方向）
    private fun selftestPing() {
        val s = session ?: return
        val ip = peerInput.text.toString().trim()
            .ifEmpty { run {
                for (i in 0 until s.memberCount()) {
                    val m = s.memberAt(i)
                    if (m.connected) return@run m.virtualIP ?: ""
                }
                ""
            } }
        if (ip.isEmpty()) {
            appendLog("自测 ping: 没有可测试的节点 IP")
            return
        }
        Thread {
            val ok = try {
                java.net.InetAddress.getByName(ip).isReachable(1500)
            } catch (e: Exception) {
                false
            }
            ui.post { appendLog("自测 ping $ip: ${if (ok) "成功" else "超时"}")
                if (!ok) appendLog("（若出站也不通，说明 VPN 路由对 App 流量也未生效）") }
        }.start()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // VPN 服务的诊断信息显示到本 App 日志
        MeshVpnService.logHook = { msg -> ui.post { appendLog("[vpn] $msg") } }

        serverInput = findViewById(R.id.serverInput)
        roomInput = findViewById(R.id.roomInput)
        tokenInput = findViewById(R.id.tokenInput)
        userInput = findViewById(R.id.userInput)
        secretInput = findViewById(R.id.secretInput)
        statusText = findViewById(R.id.statusText)
        memberText = findViewById(R.id.memberText)
        logText = findViewById(R.id.logText)
        peerInput = findViewById(R.id.peerInput)
        msgInput = findViewById(R.id.msgInput)

        findViewById<Button>(R.id.connectBtn).setOnClickListener { connect() }
        findViewById<Button>(R.id.disconnectBtn).setOnClickListener { disconnect() }
        findViewById<Button>(R.id.sendBtn).setOnClickListener { sendTo() }
        findViewById<Button>(R.id.vpnBtn).setOnClickListener { toggleVpn() }
        findViewById<Button>(R.id.broadcastBtn).setOnClickListener { broadcast() }
        findViewById<Button>(R.id.pingBtn).setOnClickListener { selftestPing() }
    }

    // VPN 真组网：请求用户授权后启动前台 VPN 服务
    private fun toggleVpn() {
        if (vpnRunning) {
            stopService(Intent(this, MeshVpnService::class.java))
            vpnRunning = false
            findViewById<Button>(R.id.vpnBtn).text = "VPN 组网"
            appendLog("VPN 已关闭")
            return
        }
        val server = serverInput.text.toString().trim()
        val room = roomInput.text.toString().trim()
        if (server.isEmpty() || room.isEmpty()) {
            statusText.text = "请填写：服务器、房间"
            return
        }
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            startActivityForResult(prepare, REQ_VPN)
        } else {
            launchVpn(server, room)
        }
    }

    private fun launchVpn(server: String, room: String) {
        val i = Intent(this, MeshVpnService::class.java).apply {
            action = "com.example.p2pdemo.VPN_START"
            putExtra("server", server)
            putExtra("room", room)
            putExtra("token", tokenInput.text.toString().trim())
            putExtra("user", userInput.text.toString().trim())
            putExtra("secret", secretInput.text.toString().trim())
            putExtra("localStack", findViewById<CheckBox>(R.id.localStackCheck).isChecked)
        }
        startForegroundService(i)
        vpnRunning = true
        findViewById<Button>(R.id.vpnBtn).text = "关闭 VPN"
        appendLog("VPN 组网启动中，请在系统弹窗允许连接…")
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) {
            val server = serverInput.text.toString().trim()
            val room = roomInput.text.toString().trim()
            if (server.isNotEmpty() && room.isNotEmpty()) launchVpn(server, room)
        } else if (requestCode == REQ_VPN) {
            appendLog("未授权 VPN，无法开启")
        }
    }

    companion object {
        private const val REQ_VPN = 100
    }

    private fun connect() {
        if (session != null) {
            appendLog("已在连接中，请先断开再重连")
            return
        }
        val server = serverInput.text.toString().trim()
        val room = roomInput.text.toString().trim()

        val missing = buildList {
            if (server.isEmpty()) add("服务器")
            if (room.isEmpty()) add("房间")
        }
        if (missing.isNotEmpty()) {
            // 单行状态提示，不往日志里堆
            statusText.text = "请填写：${missing.joinToString("、")}"
            return
        }
        val cfg = Config()
        cfg.serverAddr = server
        cfg.stunAddr = server // 单端口服务器：STUN 与信令同端口
        cfg.token = tokenInput.text.toString().trim()
        cfg.authUser = userInput.text.toString().trim()
        cfg.authSecret = secretInput.text.toString().trim()
        cfg.relayEnabled = true
        cfg.portPrediction = true
        cfg.enableLAN = true
        cfg.debug = findViewById<CheckBox>(R.id.debugCheck).isChecked

        val s = Session(cfg, listener)
        session = s
        try {
            s.connect(room)
        } catch (e: Exception) {
            appendLog("连接失败: ${e.message}")
            return
        }
        setConnecting(true)
        // 打印实际读到的值，方便确认输入是否生效
        appendLog("正在连接 server=$server room=$room")
        startEchoServer()
        ui.postDelayed({ showStatus() }, 1500)
    }

    private fun disconnect() {
        session?.disconnect()
        session = null
        setConnecting(false)
        statusText.text = "未连接"
        memberText.text = ""
    }

    // 连接期间禁用"连接"按钮，防止重复点击创建多个会话
    private fun setConnecting(connecting: Boolean) {
        findViewById<Button>(R.id.connectBtn).isEnabled = !connecting
        findViewById<Button>(R.id.disconnectBtn).isEnabled = connecting
    }

    private fun handleEvent(event: Long, peerID: String, data: ByteArray) {
        when (event) {
            P2p.EventStateChanged -> {
                val state = String(data)
                appendLog("状态: $state")
                if (state == P2p.StateConnecting) showStatus()
                if (state == P2p.StateFailed || state == P2p.StateClosed) {
                    session = null
                    setConnecting(false)
                }
            }
            P2p.EventPeerJoined -> {
                appendLog("节点加入: $peerID")
                refreshMembers()
            }
            P2p.EventPeerLeft -> {
                appendLog("节点离开: $peerID")
                refreshMembers()
            }
            P2p.EventPeerConnected -> {
                val transport = String(data) // "punched" 或 "relay"
                appendLog("已连通 $peerID via $transport")
                refreshMembers()
            }
            P2p.EventData -> {
                // peerID 为源节点虚拟 IP
                appendLog("[$peerID] ${String(data)}")
            }
            P2p.EventError -> appendLog("错误: ${String(data)}")
            P2p.EventDebug -> appendLog("[打洞] ${String(data)}")
        }
    }

    private fun showStatus() {
        val s = session ?: return
        val ip = s.localIP()
        val subnet = s.subnet()
        statusText.text = if (ip.isNullOrEmpty()) {
            "本机虚拟 IP: 未分配"
        } else {
            "本机虚拟 IP: $ip / $subnet"
        }
    }

    private fun refreshMembers() {
        val s = session ?: return
        val sb = StringBuilder()
        val n = s.memberCount()
        for (i in 0 until n) {
            val m = s.memberAt(i)
            val state = if (m.connected) (m.transport ?: "connected") else "down"
            sb.append("${m.virtualIP}  [$state]\n")
        }
        if (n == 0L) sb.append("（暂无其他节点）")
        memberText.text = sb.toString()
    }

    private fun sendTo() {
        val s = session ?: return
        val ip = peerInput.text.toString().trim()
        val text = msgInput.text.toString().trim()
        if (ip.isEmpty() || text.isEmpty()) {
            appendLog("请填写目标虚拟 IP 与消息")
            return
        }
        try {
            s.sendToIP(ip, text.toByteArray(Charsets.UTF_8))
            appendLog("发送到 $ip: $text")
        } catch (e: Exception) {
            appendLog("发送失败: ${e.message}")
        }
    }

    private fun broadcast() {
        val s = session ?: return
        val text = msgInput.text.toString().trim()
        if (text.isEmpty()) {
            appendLog("请填写消息内容")
            return
        }
        try {
            s.broadcast(text.toByteArray(Charsets.UTF_8))
            appendLog("广播: $text")
        } catch (e: Exception) {
            appendLog("广播失败: ${e.message}")
        }
    }

    private fun appendLog(line: String) {
        logText.append("$line\n")
        // 只滚动日志区，输入区保持固定
        findViewById<android.widget.ScrollView>(R.id.logScroll).post {
            findViewById<android.widget.ScrollView>(R.id.logScroll)
                .fullScroll(android.view.View.FOCUS_DOWN)
        }
    }

    override fun onDestroy() {
        session?.disconnect()
        session = null
        super.onDestroy()
    }
}
