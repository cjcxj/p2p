package com.example.p2pdemo

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import com.example.p2pdemo.databinding.ActivityMainBinding
import p2p.P2p
import java.net.InetAddress
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors

/**
 * Demo 主界面：连接 / 消息 / 节点列表 / VPN 开关。
 *
 * 职责边界：
 * - 会话细节在 MeshClient；
 * - VPN 隧道细节在 MeshVpnService；
 * - 本类只负责输入校验、UI 状态和日志展示。
 */
class MainActivity : Activity() {

    private lateinit var binding: ActivityMainBinding

    private val ui = Handler(Looper.getMainLooper())
    private val prefs by lazy { getSharedPreferences(PREF_NAME, MODE_PRIVATE) }
    private val background = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "activity-bg").apply { isDaemon = true }
    }

    private val client by lazy { MeshClient(ui, meshEvents) }

    private val logLines = ArrayDeque<String>()
    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)

    private var vpnRunning = false
    private var vpnStarting = false
    private var pendingVpnRequest: VpnRequest? = null

    private val meshEvents = object : MeshClient.EventListener {
        override fun onStateChanged(state: String) = handleState(state)

        override fun onPeerJoined(virtualIp: String, peerId: String) {
            appendLog("节点加入: $virtualIp (${shortId(peerId)})")
            if (binding.peerInput.text.isBlank()) {
                binding.peerInput.setText(virtualIp)
            }
            refreshMembers()
        }

        override fun onPeerLeft(virtualIp: String, peerId: String) {
            appendLog("节点离开: $virtualIp (${shortId(peerId)})")
            refreshMembers()
        }

        override fun onPeerConnected(virtualIp: String, transport: String, endpoint: String) {
            if (endpoint.isNotEmpty()) {
                appendLog("已连通 $virtualIp via ${transportLabel(transport)}（$endpoint）")
            } else {
                appendLog("已连通 $virtualIp via ${transportLabel(transport)}")
            }
            refreshMembers()
        }

        override fun onPeerPathChanged(virtualIp: String, transport: String) {
            appendLog("$virtualIp 切换链路: ${transportLabel(transport)}")
            refreshMembers()
        }

        override fun onData(peerIp: String, data: ByteArray) {
            appendLog("[$peerIp] ${String(data, Charsets.UTF_8)}")
        }

        override fun onError(message: String) {
            appendLog("错误: $message")
            binding.statusText.text = getString(R.string.status_connect_failed) + ": $message"
        }

        override fun onDebug(message: String) {
            appendLog("[打洞] $message")
        }
    }

    private val serviceEvents = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                AppBus.ACTION_LOG ->
                    intent.getStringExtra(AppBus.EXTRA_MESSAGE)?.let(::appendLog)
                AppBus.ACTION_VPN_STATE ->
                    onVpnState(intent.getBooleanExtra(AppBus.EXTRA_RUNNING, false))
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        restoreInputs()
        wireUi()
        updateConnectionUi(false)
        updateVpnUi(false)
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter().apply {
            addAction(AppBus.ACTION_LOG)
            addAction(AppBus.ACTION_VPN_STATE)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(serviceEvents, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(serviceEvents, filter)
        }
    }

    override fun onStop() {
        saveInputs()
        unregisterReceiver(serviceEvents)
        super.onStop()
    }

    override fun onDestroy() {
        client.disconnect()
        background.shutdownNow()
        ui.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == REQ_VPN) {
            val request = pendingVpnRequest
            pendingVpnRequest = null
            if (resultCode == RESULT_OK && request != null) {
                launchVpn(request)
            } else {
                appendLog("未授权 VPN，无法开启")
            }
            return
        }
        super.onActivityResult(requestCode, resultCode, data)
    }

    private fun wireUi() {
        binding.advToggle.setOnClickListener { toggleAdvanced() }
        binding.connectBtn.setOnClickListener { connect() }
        binding.disconnectBtn.setOnClickListener { disconnect() }
        binding.vpnBtn.setOnClickListener { toggleVpn() }
        binding.sendBtn.setOnClickListener { sendToPeer() }
        binding.broadcastBtn.setOnClickListener { broadcast() }
        binding.pingBtn.setOnClickListener { selfPing() }
        binding.clearLogBtn.setOnClickListener { clearLog() }
    }

    // ---------- 普通组网会话 ----------

    private fun connect() {
        if (client.isConnected) {
            appendLog("已在连接中，请先断开再重连")
            return
        }
        val server = binding.serverInput.text.toString().trim()
        val room = binding.roomInput.text.toString().trim()
        if (server.isEmpty() || room.isEmpty()) {
            binding.statusText.text = getString(R.string.status_fill_server_room)
            return
        }
        try {
            client.connect(buildMeshConfig(server, room))
            updateConnectionUi(true)
            binding.statusText.text = getString(R.string.status_connecting)
            appendLog("正在连接 server=$server room=$room")
        } catch (e: Exception) {
            updateConnectionUi(false)
            binding.statusText.text = getString(R.string.status_connect_failed)
            appendLog("连接失败: ${e.message}")
        }
    }

    private fun disconnect() {
        client.disconnect()
        updateConnectionUi(false)
        binding.statusText.text = getString(R.string.status_disconnected)
        binding.memberText.text = ""
    }

    private fun handleState(state: String) {
        when (state) {
            P2p.StateConnecting -> binding.statusText.text = getString(R.string.status_connecting)
            P2p.StateConnected -> refreshStatus()
            P2p.StateFailed -> {
                updateConnectionUi(false)
                binding.statusText.text = getString(R.string.status_connect_failed)
            }
            P2p.StateClosed -> {
                updateConnectionUi(false)
                binding.statusText.text = getString(R.string.status_disconnected)
                binding.memberText.text = ""
            }
        }
    }

    private fun refreshStatus() {
        val ip = client.localIp() ?: "未分配"
        val subnet = client.subnet() ?: "?"
        val nat = client.natType() ?: "?"
        binding.statusText.text = "本机虚拟 IP: $ip / $subnet（NAT: $nat）"
        refreshMembers()
    }

    private fun refreshMembers() {
        val peers = client.peers()
        binding.memberText.text = if (peers.isEmpty()) {
            getString(R.string.members_empty)
        } else {
            peers.joinToString("\n") { peer ->
                val ip = peer.virtualIp.ifBlank { "?" }
                val state = if (peer.connected) transportLabel(peer.transport) else "down"
                val endpoint = if (peer.connected && peer.endpoint.isNotEmpty()) " ${peer.endpoint}" else ""
                "$ip  [$state$endpoint]"
            }
        }
    }

    private fun sendToPeer() {
        val ip = binding.peerInput.text.toString().trim()
        val message = binding.msgInput.text.toString().trim()
        if (ip.isEmpty() || message.isEmpty()) {
            appendLog("请填写目标虚拟 IP 和消息")
            return
        }
        try {
            client.sendToIp(ip, message.toByteArray(Charsets.UTF_8))
            appendLog("发送到 $ip: $message")
        } catch (e: Exception) {
            appendLog("发送失败: ${e.message}")
        }
    }

    private fun broadcast() {
        val message = binding.msgInput.text.toString().trim()
        if (message.isEmpty()) {
            appendLog("请填写消息内容")
            return
        }
        try {
            client.broadcast(message.toByteArray(Charsets.UTF_8))
            appendLog("广播: $message")
        } catch (e: Exception) {
            appendLog("广播失败: ${e.message}")
        }
    }

    private fun selfPing() {
        val ip = binding.peerInput.text.toString().trim().ifBlank {
            client.peers().firstOrNull { it.connected }?.virtualIp.orEmpty()
        }
        if (ip.isEmpty()) {
            appendLog("自测 ping: 没有可测试的节点 IP")
            return
        }
        background.execute {
            val reachable = try {
                InetAddress.getByName(ip).isReachable(PING_TIMEOUT_MS)
            } catch (_: Exception) {
                false
            }
            ui.post {
                appendLog("自测 ping $ip: ${if (reachable) "成功" else "超时"}")
            }
        }
    }

    // ---------- VPN 组网 ----------

    private fun toggleVpn() {
        if (vpnRunning) {
            stopVpn()
            return
        }
        val server = binding.serverInput.text.toString().trim()
        val room = binding.roomInput.text.toString().trim()
        if (server.isEmpty() || room.isEmpty()) {
            binding.statusText.text = getString(R.string.status_fill_server_room)
            return
        }
        val request = VpnRequest(
            server = server,
            room = room,
            token = binding.tokenInput.text.toString().trim(),
            authUser = binding.userInput.text.toString().trim(),
            authSecret = binding.secretInput.text.toString().trim(),
            localStack = binding.localStackCheck.isChecked,
            relayEnabled = binding.relayCheck.isChecked,
            debug = binding.debugCheck.isChecked,
            plaintext = binding.plaintextCheck.isChecked,
        )
        val consent = VpnService.prepare(this)
        if (consent != null) {
            pendingVpnRequest = request
            startActivityForResult(consent, REQ_VPN)
            appendLog("请在系统弹窗中允许 VPN 连接")
        } else {
            launchVpn(request)
        }
    }

    private fun launchVpn(request: VpnRequest) {
        val intent = Intent(this, MeshVpnService::class.java)
            .setAction(MeshVpnService.ACTION_START)
            .putExtra(MeshVpnService.EXTRA_SERVER, request.server)
            .putExtra(MeshVpnService.EXTRA_ROOM, request.room)
            .putExtra(MeshVpnService.EXTRA_TOKEN, request.token)
            .putExtra(MeshVpnService.EXTRA_AUTH_USER, request.authUser)
            .putExtra(MeshVpnService.EXTRA_AUTH_SECRET, request.authSecret)
            .putExtra(MeshVpnService.EXTRA_LOCAL_STACK, request.localStack)
            .putExtra(MeshVpnService.EXTRA_RELAY, request.relayEnabled)
            .putExtra(MeshVpnService.EXTRA_DEBUG, request.debug)
            .putExtra(MeshVpnService.EXTRA_PLAINTEXT, request.plaintext)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        vpnStarting = true
        updateVpnUi(false)
        appendLog("VPN 组网启动中…")
    }

    private fun stopVpn() {
        stopService(Intent(this, MeshVpnService::class.java))
        vpnRunning = false
        vpnStarting = false
        updateVpnUi(false)
    }

    private fun onVpnState(running: Boolean) {
        vpnRunning = running
        vpnStarting = false
        updateVpnUi(running)
    }

    // ---------- UI 状态 ----------

    private fun updateConnectionUi(hasSession: Boolean) {
        binding.connectBtn.isEnabled = !hasSession
        binding.disconnectBtn.isEnabled = hasSession
        binding.sendBtn.isEnabled = hasSession
        binding.broadcastBtn.isEnabled = hasSession
        updatePingEnabled()
    }

    private fun updateVpnUi(running: Boolean) {
        binding.vpnBtn.isEnabled = !vpnStarting
        binding.vpnBtn.text = when {
            running -> getString(R.string.vpn_off)
            vpnStarting -> getString(R.string.vpn_starting)
            else -> getString(R.string.vpn_on)
        }
        updatePingEnabled()
    }

    private fun updatePingEnabled() {
        binding.pingBtn.isEnabled = client.isConnected || vpnRunning
    }

    private fun toggleAdvanced() {
        val expanded = binding.advPanel.visibility == View.VISIBLE
        binding.advPanel.visibility = if (expanded) View.GONE else View.VISIBLE
        binding.advToggle.text = getString(
            if (expanded) R.string.advanced_expand else R.string.advanced_collapse
        )
    }

    private fun clearLog() {
        logLines.clear()
        binding.logText.text = ""
    }

    private fun appendLog(message: String) {
        val line = "${timeFormat.format(Date())} $message"
        logLines.addLast(line)
        while (logLines.size > MAX_LOG_LINES) {
            logLines.removeFirst()
        }
        binding.logText.text = logLines.joinToString("\n")
        binding.logScroll.post { binding.logScroll.fullScroll(View.FOCUS_DOWN) }
    }

    // ---------- 输入持久化 ----------

    private fun restoreInputs() {
        binding.serverInput.setText(prefs.getString(KEY_SERVER, ""))
        binding.roomInput.setText(prefs.getString(KEY_ROOM, ""))
        binding.tokenInput.setText(prefs.getString(KEY_TOKEN, ""))
        binding.userInput.setText(prefs.getString(KEY_USER, ""))
        binding.secretInput.setText(prefs.getString(KEY_SECRET, ""))
        binding.relayCheck.isChecked = prefs.getBoolean(KEY_RELAY, true)
        binding.debugCheck.isChecked = prefs.getBoolean(KEY_DEBUG, false)
        binding.plaintextCheck.isChecked = prefs.getBoolean(KEY_PLAINTEXT, false)
        binding.localStackCheck.isChecked = prefs.getBoolean(KEY_LOCAL_STACK, false)
    }

    private fun saveInputs() {
        prefs.edit()
            .putString(KEY_SERVER, binding.serverInput.text.toString().trim())
            .putString(KEY_ROOM, binding.roomInput.text.toString().trim())
            .putString(KEY_TOKEN, binding.tokenInput.text.toString().trim())
            .putString(KEY_USER, binding.userInput.text.toString().trim())
            .putString(KEY_SECRET, binding.secretInput.text.toString().trim())
            .putBoolean(KEY_RELAY, binding.relayCheck.isChecked)
            .putBoolean(KEY_DEBUG, binding.debugCheck.isChecked)
            .putBoolean(KEY_PLAINTEXT, binding.plaintextCheck.isChecked)
            .putBoolean(KEY_LOCAL_STACK, binding.localStackCheck.isChecked)
            .apply()
    }

    private fun buildMeshConfig(server: String, room: String): MeshConfig = MeshConfig(
        serverAddr = server,
        room = room,
        token = binding.tokenInput.text.toString().trim(),
        authUser = binding.userInput.text.toString().trim(),
        authSecret = binding.secretInput.text.toString().trim(),
        relayEnabled = binding.relayCheck.isChecked,
        portPrediction = true,
        enableLan = true,
        debug = binding.debugCheck.isChecked,
        plaintext = binding.plaintextCheck.isChecked,
    )

    private fun transportLabel(transport: String): String = when (transport) {
        P2p.TransportPunched -> "直连"
        P2p.TransportRelay -> "中继"
        else -> transport.ifBlank { "connected" }
    }

    private fun shortId(peerId: String): String =
        if (peerId.length <= 8) peerId else peerId.take(8)

    companion object {
        private const val REQ_VPN = 100
        private const val MAX_LOG_LINES = 400
        private const val PING_TIMEOUT_MS = 1500
        private const val PREF_NAME = "mesh_demo"

        private const val KEY_SERVER = "server"
        private const val KEY_ROOM = "room"
        private const val KEY_TOKEN = "token"
        private const val KEY_USER = "user"
        private const val KEY_SECRET = "secret"
        private const val KEY_RELAY = "relay"
        private const val KEY_DEBUG = "debug"
        private const val KEY_PLAINTEXT = "plaintext"
        private const val KEY_LOCAL_STACK = "local_stack"
    }
}
