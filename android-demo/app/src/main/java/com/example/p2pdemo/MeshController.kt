package com.example.p2pdemo

import android.content.Context
import android.content.Intent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import p2p.Listener
import p2p.P2p
import p2p.Session
import p2p.SocketProtector

/**
 * 全应用唯一的组网会话。
 *
 * 旧实现里 MainActivity 建了一个 Session、VpnService 又建一个，两个会话各自拿到
 * 一个虚拟 IP，同一台手机对自己打洞，界面显示的节点表和真正跑的链路也不是同一份。
 * 这里只保留一个 Session：UI、VPN 服务、自测工具都通过控制器读写同一份状态。
 *
 * SDK 的事件回调来自 Go 线程，不能在里面做任何慢事——统一塞进无界通道，由
 * [reduce] 协程消费；会话快照（节点表、虚拟 IP）另由 2 秒心跳重读，避免漏掉
 * 没有事件承载的 endpoint / NAT 变化。
 */
class MeshController(context: Context) {

    private val appContext = context.applicationContext
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val lifecycle = Mutex()
    private val testing = Mutex()
    private val events = Channel<SdkEvent>(Channel.UNLIMITED)

    private val _state = MutableStateFlow(
        MeshUiState(
            config = Prefs.load(appContext),
            targetIp = Prefs.loadTarget(appContext),
        )
    )
    val state: StateFlow<MeshUiState> = _state.asStateFlow()

    private val _logs = MutableStateFlow<List<LogLine>>(emptyList())
    val logs: StateFlow<List<LogLine>> = _logs.asStateFlow()

    @Volatile
    private var session: Session? = null

    @Volatile
    private var activeConfig: ConnConfig? = null

    private var echoServer: TcpEchoServer? = null

    private val protector = SocketProtector { fd -> VpnBridge.protect(fd) }

    private val listener = Listener { event, peerID, data ->
        events.trySend(SdkEvent(event, peerID, String(data, Charsets.UTF_8)))
    }

    init {
        scope.launch {
            for (e in events) reduce(e)
        }
        scope.launch {
            while (true) {
                delay(REFRESH_MS)
                if (session != null) snapshot()
            }
        }
        log(LogKind.Info, "就绪：填写服务器地址与房间名后打开“接入组网”")
    }

    // ---------- 对外动作 ----------

    /** 一键接入：连上房间，再挂上虚拟网卡。 */
    fun startAll() {
        scope.launch {
            val cfg = currentConfig()
            val connected = lifecycle.withLock { doConnect(cfg) }
            if (connected) doSetTunnel(true)
        }
    }

    fun connect() {
        scope.launch { lifecycle.withLock { doConnect(currentConfig()) } }
    }

    fun disconnect() {
        scope.launch {
            lifecycle.withLock {
                doSetTunnel(false, "离开房间前已收掉虚拟网卡")
                doDisconnect()
            }
            // 服务只为虚拟网卡存在，房间一走它就没有存在意义了。
            stopVpnService()
        }
    }

    /** 只开关隧道，会话保持——这是虚拟网卡开关的正确语义。 */
    fun setTunnel(on: Boolean) {
        scope.launch {
            lifecycle.withLock {
                if (doSetTunnel(on) && !on) stopVpnService()
            }
        }
    }

    fun saveConfig(cfg: ConnConfig) {
        Prefs.save(appContext, cfg)
        updateState { copy(config = cfg) }
        val old = activeConfig
        if (old != null && old != cfg) {
            log(LogKind.Info, "连接参数已保存，下次接入时生效")
        }
    }

    fun selectTarget(ip: String) {
        Prefs.saveTarget(appContext, ip)
        updateState { copy(targetIp = ip, test = TestRun()) }
    }

    fun runPing() {
        scope.launch {
            val host = _state.value.targetIp
            if (host.isEmpty()) {
                log(LogKind.Error, "还没有测试目标，先在节点列表里点选一个")
                return@launch
            }
            testing.withLock {
                updateState { copy(test = TestRun(TestKind.Ping, host, running = true)) }
                val r = withContext(Dispatchers.IO) { NetTools.ping(host) }
                updateState { copy(test = TestRun(TestKind.Ping, host, ok = r.reachable, summary = r.detail)) }
                log(if (r.reachable) LogKind.Info else LogKind.Error, "ping $host：${r.detail}")
            }
        }
    }

    fun runEcho() {
        scope.launch {
            val host = _state.value.targetIp
            if (host.isEmpty()) {
                log(LogKind.Error, "还没有测试目标，先在节点列表里点选一个")
                return@launch
            }
            testing.withLock {
                updateState { copy(test = TestRun(TestKind.Echo, host, running = true)) }
                val r = withContext(Dispatchers.IO) {
                    NetTools.tcpEcho(host, ECHO_PORT, PING_PAYLOAD)
                }
                val summary = if (r.ok) {
                    "往返 ${r.rttMs} ms，回包“${r.reply.trim()}”"
                } else {
                    r.error.ifEmpty { "无回包" }
                }
                updateState { copy(test = TestRun(TestKind.Echo, host, ok = r.ok, summary = summary)) }
                log(if (r.ok) LogKind.Info else LogKind.Error, "tcp $host:$ECHO_PORT：$summary")
            }
        }
    }

    fun clearLogs() {
        _logs.value = emptyList()
    }

    /** 手动“刷新”：立刻重读一次会话快照，不等 2 秒心跳。 */
    fun refreshNow() {
        scope.launch { snapshot() }
    }

    /** 服务、系统回调等外部来源的日志入口，取代以前的广播总线。 */
    fun appendExternalLog(text: String) {
        log(LogKind.Tunnel, text)
    }

    // ---------- 会话 ----------

    private suspend fun doConnect(cfg: ConnConfig): Boolean {
        if (!cfg.isValid) {
            setError("服务器地址和房间名都不能为空")
            return false
        }
        val existing = session
        if (existing != null && activeConfig != cfg) {
            log(LogKind.Info, "参数已变更，重建会话")
            doSetTunnel(false)
            doDisconnect()
        }
        val s = session ?: createSession(cfg) ?: return false
        if (_state.value.phase == SessionPhase.Connected && _state.value.localIp.isNotEmpty()) {
            return true
        }
        updateState { copy(busy = true, error = "", phase = SessionPhase.Connecting) }
        return try {
            s.connect(cfg.room)
            val vip = awaitVip(s)
            if (vip == null) {
                updateState { copy(phase = SessionPhase.Failed) }
                if (_state.value.error.isEmpty()) {
                    setError("连接超时：信令无响应或房间不可达")
                }
                log(LogKind.Error, "连接失败，已断开")
                doDisconnect()
                false
            } else {
                val nat = s.natType().orEmpty()
                val subnet = s.subnet().orEmpty().ifEmpty { DEFAULT_SUBNET }
                updateState {
                    copy(
                        phase = SessionPhase.Connected,
                        localIp = vip,
                        subnet = subnet,
                        natType = nat,
                    )
                }
                log(LogKind.Info, "已接入房间 ${cfg.room}：本机 $vip，NAT $nat")
                startEcho()
                snapshot()
                true
            }
        } catch (e: Exception) {
            updateState { copy(phase = SessionPhase.Failed, error = e.message ?: "连接异常") }
            log(LogKind.Error, "连接异常：${e.message}")
            doDisconnect()
            false
        } finally {
            updateState { copy(busy = false) }
        }
    }

    private fun createSession(cfg: ConnConfig): Session? {
        return try {
            val s = Session(cfg.toP2p(), listener)
            s.setSocketProtector(protector)
            session = s
            activeConfig = cfg
            s
        } catch (e: Exception) {
            updateState { copy(phase = SessionPhase.Failed, error = e.message ?: "会话创建失败") }
            log(LogKind.Error, "会话创建失败：${e.message}")
            null
        }
    }

    private suspend fun awaitVip(s: Session): String? {
        var waited = 0L
        while (waited < VIP_TIMEOUT_MS) {
            val ip = s.localIP().orEmpty()
            if (ip.isNotEmpty()) return ip
            if (_state.value.phase == SessionPhase.Failed || _state.value.phase == SessionPhase.Closed) {
                return null
            }
            delay(VIP_POLL_MS)
            waited += VIP_POLL_MS
        }
        return null
    }

    private fun doDisconnect() {
        val s = session
        session = null
        activeConfig = null
        stopEcho()
        s?.disconnect()
        updateState {
            copy(
                phase = SessionPhase.Closed,
                localId = "",
                localIp = "",
                subnet = "",
                peers = emptyList(),
                tunnel = TunnelPhase.Off,
                tunName = "",
            )
        }
        log(LogKind.Info, "已离开房间")
    }

    // ---------- 隧道 ----------

    private suspend fun doSetTunnel(on: Boolean, offReason: String = "虚拟网卡已关闭，房间会话保持"): Boolean {
        val st = _state.value
        if (on) {
            if (st.tunnel == TunnelPhase.On) return true
            val s = session ?: run {
                setError("还没有会话，先接入房间")
                return false
            }
            val vip = st.localIp.ifEmpty { s.localIP().orEmpty() }
            if (vip.isEmpty()) {
                setError("房间尚未分配虚拟 IP，稍后重试")
                return false
            }
            updateState { copy(tunnel = TunnelPhase.Starting, error = "") }
            if (!awaitBridge()) {
                updateState { copy(tunnel = TunnelPhase.Off) }
                setError("VPN 服务未就绪，权限可能被拒绝")
                return false
            }
            val subnet = st.subnet.ifEmpty { s.subnet().orEmpty() }.ifEmpty { DEFAULT_SUBNET }
            val fd = VpnBridge.openTunFd(vip, subnet)
            if (fd < 0L) {
                updateState { copy(tunnel = TunnelPhase.Off) }
                log(LogKind.Error, "虚拟网卡建立失败")
                return false
            }
            // 接口一起来，本机全部流量都会被重新路由。mesh 的 UDP socket 必须在这之后
            // 摘出隧道，否则打洞包会绕回自己，链路永远建不起来。
            s.setSocketProtector(protector)
            try {
                // 描述符从这里起归 SDK：成功失败它都会关闭，这里再关会误伤复用的编号。
                s.attachTUN(fd, VpnBridge.MTU.toLong())
            } catch (e: Exception) {
                updateState { copy(tunnel = TunnelPhase.Off) }
                log(LogKind.Error, "挂载隧道失败：${e.message}")
                return false
            }
            val name = s.tunName().orEmpty().ifEmpty { "p2p-tun" }
            updateState { copy(tunnel = TunnelPhase.On, tunName = name) }
            log(LogKind.Tunnel, "虚拟网卡已接入 $vip/$subnet（MTU ${VpnBridge.MTU}）")
            snapshot()
            return true
        }
        if (st.tunnel == TunnelPhase.Off) return true
        session?.closeTUN()
        updateState { copy(tunnel = TunnelPhase.Off, tunName = "") }
        log(LogKind.Tunnel, offReason)
        return true
    }

    /** 服务启动与这里并发：等 capability 注册好，最多 2 秒。 */
    private suspend fun awaitBridge(): Boolean {
        var waited = 0L
        while (!VpnBridge.available && waited < BRIDGE_TIMEOUT_MS) {
            delay(BRIDGE_POLL_MS)
            waited += BRIDGE_POLL_MS
        }
        return VpnBridge.available
    }

    private fun stopVpnService() {
        try {
            appContext.stopService(Intent(appContext, MeshVpnService::class.java))
        } catch (_: Exception) {
        }
    }

    // ---------- 快照与事件 ----------

    private fun snapshot() {
        val s = session ?: return
        val rows = ArrayList<PeerRow>(8)
        val count = runCatching { s.memberCount() }.getOrDefault(0L)
        var index = 0L
        while (index < count) {
            val m = runCatching { s.memberAt(index) }.getOrNull()
            if (m != null) {
                rows.add(
                    PeerRow(
                        virtualIp = m.getVirtualIP().orEmpty(),
                        peerId = m.getPeerID().orEmpty(),
                        transport = m.getTransport().orEmpty(),
                        endpoint = m.getEndpoint().orEmpty(),
                        natType = m.getNATType().orEmpty(),
                        connected = m.getConnected(),
                    )
                )
            }
            index++
        }
        // 一次性读完再写状态：update 的 lambda 可能重试，重试时不该再回调 Go。
        val vip = s.localIP().orEmpty()
        val subnet = s.subnet().orEmpty()
        val nat = s.natType().orEmpty()
        val name = s.tunName().orEmpty()
        val id = s.localID().orEmpty()
        _state.update { prev ->
            prev.copy(
                peers = rows.sortedWith(compareBy({ !it.connected }, { it.virtualIp })),
                localId = id.ifEmpty { prev.localId },
                localIp = vip.ifEmpty { prev.localIp },
                natType = nat.ifEmpty { prev.natType },
                subnet = subnet.ifEmpty { prev.subnet },
                tunName = name.ifEmpty { prev.tunName },
            )
        }
    }

    private fun reduce(e: SdkEvent) {
        when (e.event) {
            P2p.EventStateChanged -> {
                val phase = sessionPhaseOf(e.data)
                when (phase) {
                    SessionPhase.Connected -> {
                        val s = session
                        val vip = s?.localIP().orEmpty()
                        val subnet = s?.subnet().orEmpty()
                        _state.update { prev ->
                            prev.copy(
                                phase = phase,
                                error = "",
                                localIp = vip.ifEmpty { prev.localIp },
                                subnet = subnet.ifEmpty { prev.subnet },
                            )
                        }
                        snapshot()
                    }
                    SessionPhase.Closed, SessionPhase.Failed -> {
                        if (phase == SessionPhase.Failed) {
                            log(LogKind.Error, "会话中断：${e.data}")
                        }
                        _state.update { prev ->
                            prev.copy(
                                phase = phase,
                                tunnel = TunnelPhase.Off,
                                tunName = "",
                                peers = emptyList(),
                            )
                        }
                    }
                    else -> {
                        _state.update { prev -> prev.copy(phase = phase) }
                    }
                }
            }

            P2p.EventPeerJoined -> {
                log(LogKind.Info, "节点加入 ${e.peerID}（${shortId(e.data)}）")
                snapshot()
            }

            P2p.EventPeerLeft -> {
                log(LogKind.Info, "节点离开 ${e.peerID}")
                snapshot()
            }

            P2p.EventPeerConnected -> {
                log(LogKind.Info, "节点 ${e.peerID} 已连通：${linkOf(e.data)}")
                snapshot()
            }

            P2p.EventPathChanged -> {
                log(LogKind.Tunnel, "节点 ${e.peerID} 切换路径：${linkOf(e.data)}")
                snapshot()
            }

            P2p.EventError -> {
                updateState { copy(error = e.data) }
                log(LogKind.Error, e.data)
            }

            P2p.EventDebug -> log(LogKind.Punch, e.data)

            else -> Unit
        }
    }

    private fun log(kind: LogKind, text: String) {
        _logs.update { lines ->
            (lines + LogLine(System.currentTimeMillis(), kind, text)).takeLast(MAX_LOGS)
        }
    }

    private fun setError(message: String) {
        updateState { copy(error = message) }
        log(LogKind.Error, message)
    }

    private inline fun updateState(block: MeshUiState.() -> MeshUiState) {
        _state.update { it.run(block) }
    }

    private fun currentConfig(): ConnConfig {
        val cfg = Prefs.load(appContext)
        updateState { copy(config = cfg) }
        return cfg
    }

    private fun startEcho() {
        if (echoServer?.isRunning == true) return
        val server = TcpEchoServer(ECHO_PORT) { message -> log(LogKind.Info, message) }
        if (server.start()) {
            echoServer = server
            log(LogKind.Info, "本机 TCP $ECHO_PORT 已监听，其他节点可通过虚拟 IP 连接")
        } else {
            log(LogKind.Error, "TCP $ECHO_PORT 监听失败（端口被占用？）")
        }
    }

    private fun stopEcho() {
        echoServer?.stop()
        echoServer = null
    }

    private fun shortId(id: String): String = if (id.length <= 8) id else id.substring(0, 8)

    private fun linkOf(transport: String): String = when (transport) {
        P2p.TransportPunched -> "直连"
        P2p.TransportRelay -> "中继"
        else -> transport.ifEmpty { "未知" }
    }

    /** SDK 回调载荷先转成可发送的小结构，避免在 Go 线程里做解析。 */
    private data class SdkEvent(
        val event: Long = 0,
        val peerID: String = "",
        val data: String = "",
    )

    companion object {
        private const val REFRESH_MS = 2_000L
        private const val VIP_TIMEOUT_MS = 30_000L
        private const val VIP_POLL_MS = 150L
        private const val BRIDGE_TIMEOUT_MS = 2_000L
        private const val BRIDGE_POLL_MS = 100L
        private const val MAX_LOGS = 400
        private const val DEFAULT_SUBNET = "10.9.0.0/24"
        const val ECHO_PORT = 7000
        private const val PING_PAYLOAD = "p2p-selftest"
    }
}
