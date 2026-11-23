package com.example.p2pdemo

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import p2p.Listener
import p2p.P2p
import p2p.Session
import p2p.SocketProtector
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * 把手机接入 mesh 虚拟子网的 VpnService。
 *
 * 数据面：
 * - tun -> mesh：只放行虚拟子网内的 IPv4 包，广播走 broadcast，单播走 sendToIP；
 * - mesh -> tun：广播 / 发往其它虚拟 IP 的包注入 tun；
 * - 发往本机虚拟 IP 的 ICMP echo：用户态协议栈开启时 SDK 已处理；
 *   未开启时由应用层代答（Android 内核不会替 tun 回包）。
 *
 * 生命周期全部通过 running / stopVpn 收敛，关闭 tun fd 即可解除阻塞读。
 */
class MeshVpnService : VpnService() {

    @Volatile
    private var session: Session? = null

    @Volatile
    private var running = false

    private var tunFd: ParcelFileDescriptor? = null
    private var tunOutput: FileOutputStream? = null
    private val tunWriteLock = Any()

    private var bridgeExecutor: ExecutorService? = null
    private var senderExecutor: ExecutorService? = null
    private var fallbackScheduler: ScheduledExecutorService? = null
    private var echoServer: TcpEchoServer? = null

    private val pendingEcho = ConcurrentHashMap.newKeySet<String>()

    @Volatile
    private var kernelIcmpFailed = false

    private var echoSinceFail = 0

    @Volatile
    private var virtualNetwork: ByteArray? = null

    @Volatile
    private var virtualPrefix = DEFAULT_PREFIX

    private val threadIds = AtomicInteger()

    private val protector = object : SocketProtector {
        override fun protect(fd: Long): Boolean =
            this@MeshVpnService.protect(fd.toInt())
    }

    private val listener = object : Listener {
        override fun onEvent(event: Long, peerID: String, data: ByteArray) {
            when (event) {
                P2p.EventData -> handleMeshPacket(data)
                P2p.EventStateChanged -> {
                    val state = data.toUtf8()
                    log("会话状态: $state")
                    if (state == P2p.StateFailed) {
                        log("VPN 会话失败，停止服务")
                        stopSelf()
                    }
                }
                P2p.EventPeerJoined -> log("节点加入: $peerID")
                P2p.EventPeerLeft -> log("节点离开: $peerID")
                P2p.EventPeerConnected ->
                    log("节点已连通: $peerID via ${data.toUtf8()}")
                P2p.EventError -> log("错误: ${data.toUtf8()}")
                P2p.EventDebug -> log("[打洞] ${data.toUtf8()}")
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) return START_NOT_STICKY
        return when (intent.action) {
            ACTION_STOP -> {
                log("收到停止请求")
                stopVpn()
                stopSelf()
                START_NOT_STICKY
            }
            ACTION_START -> startWith(intent)
            else -> START_NOT_STICKY
        }
    }

    private fun startWith(intent: Intent): Int {
        if (running) {
            log("VPN 已在运行，忽略重复启动")
            return START_STICKY
        }
        val request = readRequest(intent)
        if (request == null) {
            log("启动参数不完整")
            stopSelf()
            return START_NOT_STICKY
        }
        try {
            startForegroundWithType()
        } catch (e: Exception) {
            log("前台服务启动失败: ${e.message}")
            stopSelf()
            return START_NOT_STICKY
        }

        running = true
        bridgeExecutor = newSingleExecutor("vpn-bridge")
        senderExecutor = newSingleExecutor("vpn-sender")
        fallbackScheduler = Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "vpn-icmp-fallback").apply { isDaemon = true }
        }
        bridgeExecutor?.execute { runVpn(request) }
        return START_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    // ---------- 组网与 VPN 接口 ----------

    private fun runVpn(request: VpnRequest) {
        val client = Session(request.toMeshConfig().toP2p(), listener)
        // 必须先 protect mesh socket，再建立 VPN，否则会把自己的流量再路由回 tun。
        client.setSocketProtector(protector)
        session = client

        try {
            client.connect(request.room)
        } catch (e: Exception) {
            log("连接失败: ${e.message}")
            stopSelf()
            return
        }

        val ip = awaitLocalIp(client)
        if (ip == null) {
            log("等待虚拟 IP 超时")
            stopSelf()
            return
        }
        val subnet = client.subnet()?.takeIf { it.isNotEmpty() } ?: DEFAULT_SUBNET

        if (request.localStack) {
            try {
                client.enableLocalStack()
                client.exposeTCP(ECHO_TCP_PORT.toLong())
                val echo = TcpEchoServer(ECHO_TCP_PORT) { message -> log(message) }
                if (echo.start()) {
                    echoServer = echo
                } else {
                    echo.stop()
                }
                log("用户态协议栈已启用，TCP $ECHO_TCP_PORT 已暴露给虚拟网")
            } catch (e: Exception) {
                log("用户态协议栈启用失败: ${e.message}（ICMP 走应用层代答，TCP 7000 不可用）")
            }
        } else {
            log("未启用用户态协议栈：ICMP 内核优先，超时后应用层代答")
        }

        val pfd = buildTun(ip, subnet)
        if (pfd == null) {
            log("VPN 接口建立失败")
            stopSelf()
            return
        }
        tunFd = pfd
        tunOutput = FileOutputStream(pfd.fileDescriptor)

        log("VPN 接口已建立: $ip/$subnet")
        AppBus.sendVpnState(this, true)
        bridgeTunToMesh(client, FileInputStream(pfd.fileDescriptor))
        log("VPN 读循环退出")
        stopSelf()
    }

    private fun awaitLocalIp(client: Session): String? {
        repeat(LOCAL_IP_WAIT_ATTEMPTS) {
            if (!running) return null
            client.localIP()?.takeIf { it.isNotEmpty() }?.let { return it }
            try {
                Thread.sleep(LOCAL_IP_POLL_MS)
            } catch (_: InterruptedException) {
                return null
            }
        }
        return null
    }

    private fun buildTun(ip: String, subnet: String): ParcelFileDescriptor? {
        val network = subnet.substringBefore('/')
        val prefix = subnet.substringAfter('/', DEFAULT_PREFIX.toString())
            .toIntOrNull()
            ?.coerceIn(0, 32)
            ?: DEFAULT_PREFIX
        val networkBytes = Ipv4.parseAddress(network)
        if (networkBytes == null) {
            log("子网地址无效: $subnet")
            return null
        }
        virtualNetwork = networkBytes
        virtualPrefix = prefix

        val builder = Builder()
            .setSession("p2p-mesh")
            .setMtu(MTU)
            .setBlocking(true)
            .addAddress(ip, prefix)
            .addRoute(network, prefix)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                val networks = cm.allNetworks
                if (networks.isNotEmpty()) {
                    builder.setUnderlyingNetworks(networks)
                    log("底层网络已绑定（${networks.size} 个）")
                } else {
                    log("警告：未获取到底层网络，VPN 路由可能不生效")
                }
            } catch (e: Exception) {
                log("绑定底层网络失败: ${e.message}")
            }
        }

        return try {
            builder.establish()
        } catch (e: Exception) {
            log("建立 VPN 接口异常: ${e.message}")
            null
        }
    }

    // ---------- tun <-> mesh 桥接 ----------

    private fun bridgeTunToMesh(client: Session, input: FileInputStream) {
        log("VPN 读循环已启动")
        val buffer = ByteArray(65536)
        while (running) {
            val read = try {
                input.read(buffer)
            } catch (e: Exception) {
                log("读循环退出: ${e.message}")
                break
            }
            if (read <= 0) break
            handleTunPacket(client, buffer.copyOf(read))
        }
    }

    /** tun -> mesh：只路由虚拟子网流量，避免把手机上网流量打进 mesh。 */
    private fun handleTunPacket(client: Session, packet: ByteArray) {
        val info = Ipv4.parse(packet) ?: run {
            Log.d(TAG, "丢弃非 IPv4 包（${packet.size} 字节）")
            return
        }
        // 内核产生的 ICMP echo reply：说明内核 TUN 能正常回包，取消待定的应用层兜底。
        if (Ipv4.isIcmpEchoReply(packet)) {
            val key = Ipv4.icmpEchoKey(packet)
            if (key != null && pendingEcho.remove(key) && kernelIcmpFailed) {
                kernelIcmpFailed = false
                log("检测到内核 ICMP 回包，恢复内核优先")
            }
        }
        val me = session?.localIP()
        if (me != null && info.destination == me) {
            Log.d(TAG, "丢弃发往本机虚拟 IP 的回环包")
            return
        }
        val network = virtualNetwork ?: return
        if (!Ipv4.inSubnet(info.destinationBytes, network, virtualPrefix)) {
            Log.d(TAG, "丢弃非虚拟网段流量: ${info.destination} 协议 ${info.protocol}")
            return
        }

        val broadcast = Ipv4.isMulticast(info.destinationBytes) ||
            Ipv4.isSubnetBroadcast(info.destinationBytes, network, virtualPrefix) ||
            Ipv4.isLimitedBroadcast(info.destinationBytes)

        try {
            if (broadcast) {
                client.broadcast(packet)
            } else {
                client.sendToIP(info.destination, packet)
            }
        } catch (e: Exception) {
            log("mesh 发送失败: ${e.message}")
        }
    }

    /**
     * mesh -> tun。SDK 回调线程内不能反调 Session，所以 ICMP 代答放到
     * senderExecutor 里发送；写入 tun 是文件 IO，可以原地完成。
     */
    private fun handleMeshPacket(packet: ByteArray) {
        if (!running) return
        val info = Ipv4.parse(packet) ?: run {
            log("收到无效 IPv4 包，丢弃")
            return
        }
        val me = session?.localIP()
        if (me != null && info.destination == me) {
            // 用户态协议栈开启时，发给本机的包会在 SDK 内被拦截，一般走不到这里。
            val reply = Ipv4.icmpEchoReply(packet, me)
            if (reply != null) {
                val key = Ipv4.icmpEchoKey(packet)
                if (key == null) {
                    sendAppEchoReply(packet, reply, me)
                } else if (kernelIcmpFailed) {
                    // 之前内核不回包，暂时应用层代答；每 N 次复探一次内核。
                    echoSinceFail++
                    if (echoSinceFail >= KERNEL_ICMP_REPROBE_EVERY) {
                        echoSinceFail = 0
                        tryKernelThenFallback(packet, reply, key, me)
                    } else {
                        sendAppEchoReply(packet, reply, me)
                    }
                } else {
                    // 默认内核优先：先注入 TUN，等内核回包；超时未回再兜底。
                    tryKernelThenFallback(packet, reply, key, me)
                }
            } else {
                // 用户态协议栈只接管发给本机的 ICMP echo request（以及 TCP）。
                // 其它发给本机的包（例如 ping 对端后返回的 ICMP echo reply）
                // 必须注入 tun 让内核 ping socket 收到，否则手机自己 ping 不通。
                if (!injectToTun(packet)) {
                    log("注入本机回包失败（协议 ${info.protocol}）")
                }
            }
            return
        }
        injectToTun(packet)
    }

    /** 应用层 ICMP echo reply 兜底。必须在后台线程发送，不能在 SDK 回调线程里反调 Session。 */
    private fun sendAppEchoReply(request: ByteArray, reply: ByteArray, me: String) {
        val back = Ipv4.parse(reply)?.destination ?: return
        val client = session
        senderExecutor?.execute {
            try {
                client?.sendToIP(back, reply)
                log("已代答 ICMP echo -> $back")
            } catch (e: Exception) {
                log("ICMP 代答发送失败: ${e.message}")
            }
        }
    }

    /** 内核优先：注入 TUN，并在超时后发送应用层兜底 reply（若内核已回则自动取消）。 */
    private fun tryKernelThenFallback(
        request: ByteArray,
        reply: ByteArray,
        key: String,
        me: String,
    ) {
        pendingEcho.add(key)
        if (!injectToTun(request)) {
            pendingEcho.remove(key)
            sendAppEchoReply(request, reply, me)
            return
        }
        val scheduled = fallbackScheduler?.schedule({
            if (pendingEcho.remove(key)) {
                sendAppEchoReply(request, reply, me)
                kernelIcmpFailed = true
                log("内核未在 ${KERNEL_ICMP_FALLBACK_MS}ms 内回 ICMP，应用层代答")
            }
        }, KERNEL_ICMP_FALLBACK_MS, TimeUnit.MILLISECONDS)
        if (scheduled == null) {
            pendingEcho.remove(key)
            sendAppEchoReply(request, reply, me)
        }
    }

    private fun injectToTun(packet: ByteArray): Boolean {
        val output = tunOutput ?: return false
        return try {
            synchronized(tunWriteLock) {
                output.write(packet)
                output.flush()
            }
            true
        } catch (e: Exception) {
            log("写入 VPN 接口失败: ${e.message}")
            false
        }
    }

    // ---------- 生命周期 ----------

    private fun stopVpn() {
        val active = running || session != null || tunFd != null || echoServer != null
        if (!active) return

        running = false

        echoServer?.stop()
        echoServer = null

        try {
            tunOutput?.close()
        } catch (_: Exception) {
        }
        tunOutput = null

        try {
            tunFd?.close()
        } catch (_: Exception) {
        }
        tunFd = null

        session?.disconnect()
        session = null

        fallbackScheduler?.shutdownNow()
        fallbackScheduler = null
        pendingEcho.clear()
        kernelIcmpFailed = false
        echoSinceFail = 0

        bridgeExecutor?.shutdownNow()
        senderExecutor?.shutdownNow()
        bridgeExecutor = null
        senderExecutor = null

        log("VPN 已停止")
        AppBus.sendVpnState(this, false)
    }

    // ---------- 辅助 ----------

    private fun readRequest(intent: Intent): VpnRequest? {
        val server = intent.getStringExtra(EXTRA_SERVER)?.trim().orEmpty()
        val room = intent.getStringExtra(EXTRA_ROOM)?.trim().orEmpty()
        if (server.isEmpty() || room.isEmpty()) return null
        return VpnRequest(
            server = server,
            room = room,
            token = intent.getStringExtra(EXTRA_TOKEN).orEmpty(),
            authUser = intent.getStringExtra(EXTRA_AUTH_USER).orEmpty(),
            authSecret = intent.getStringExtra(EXTRA_AUTH_SECRET).orEmpty(),
            localStack = intent.getBooleanExtra(EXTRA_LOCAL_STACK, false),
            relayEnabled = intent.getBooleanExtra(EXTRA_RELAY, true),
            debug = intent.getBooleanExtra(EXTRA_DEBUG, true),
            plaintext = intent.getBooleanExtra(EXTRA_PLAINTEXT, false),
        )
    }

    private fun startForegroundWithType() {
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun buildNotification(): Notification {
        val channelId = "p2p-vpn"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(
                NotificationChannel(channelId, "P2P 组网 VPN", NotificationManager.IMPORTANCE_LOW)
            )
        }

        val contentIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, MeshVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE,
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, channelId)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("P2P 组网")
            .setContentText("虚拟局域网运行中")
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setOngoing(true)
            .setContentIntent(contentIntent)
            .addAction(0, "断开", stopIntent)
            .build()
    }

    private fun newSingleExecutor(name: String): ExecutorService =
        Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "$name-${threadIds.incrementAndGet()}").apply { isDaemon = true }
        }

    private fun log(message: String) {
        Log.i(TAG, message)
        AppBus.sendLog(this, "[vpn] $message")
    }

    private fun ByteArray.toUtf8(): String = String(this, Charsets.UTF_8)

    companion object {
        const val ACTION_START = "com.example.p2pdemo.VPN_START"
        const val ACTION_STOP = "com.example.p2pdemo.VPN_STOP"

        const val EXTRA_SERVER = "extra.server"
        const val EXTRA_ROOM = "extra.room"
        const val EXTRA_TOKEN = "extra.token"
        const val EXTRA_AUTH_USER = "extra.auth_user"
        const val EXTRA_AUTH_SECRET = "extra.auth_secret"
        const val EXTRA_LOCAL_STACK = "extra.local_stack"
        const val EXTRA_RELAY = "extra.relay"
        const val EXTRA_DEBUG = "extra.debug"
        const val EXTRA_PLAINTEXT = "extra.plaintext"

        const val ECHO_TCP_PORT = 7000

        private const val TAG = "MeshVpn"
        private const val NOTIFICATION_ID = 1001
        private const val MTU = 1280
        private const val DEFAULT_PREFIX = 24
        private const val DEFAULT_SUBNET = "10.9.0.0/24"
        private const val LOCAL_IP_WAIT_ATTEMPTS = 100
        private const val LOCAL_IP_POLL_MS = 200L
        private const val KERNEL_ICMP_FALLBACK_MS = 500L
        private const val KERNEL_ICMP_REPROBE_EVERY = 10
    }
}
