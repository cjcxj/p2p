package com.example.p2pdemo

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
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
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/**
 * 真组网：把手机的虚拟 IP 接入系统，创建 VPN 接口，
 * 让 OS 流量（ping / SSH / 网页）经 mesh 走虚拟局域网。
 */
class MeshVpnService : VpnService() {

    companion object {
        const val NOTIF_ID = 1001
        const val ACTION_START = "com.example.p2pdemo.VPN_START"
        const val ACTION_STOP = "com.example.p2pdemo.VPN_STOP"
        private const val TAG = "MeshVpn"
        private const val KERNEL_ICMP_FALLBACK_MS = 500L // 内核代答等待窗口，超时即兜底
        private const val KERNEL_ICMP_REPROBE_EVERY = 10 // 兜底期间每 10 个 echo 请求复探一次内核

        // 让 VPN 服务的诊断信息显示到 App 日志里（无需 adb）
        @Volatile
        var logHook: ((String) -> Unit)? = null
    }

    private fun log(msg: String) {
        Log.w(TAG, msg)
        logHook?.invoke(msg)
    }

    @Volatile
    private var session: Session? = null
    private var pfd: ParcelFileDescriptor? = null
    private var output: FileOutputStream? = null
    private var bridgeThread: Thread? = null
    private var running = false
    @Volatile
    private var lastReadMs = 0L
    @Volatile
    private var virtualNet: ByteArray? = null // 虚拟子网网络地址（4字节），buildVpn 时按 subnet 赋值
    @Volatile
    private var virtualPrefix = 24
    @Volatile
    private var kernelIcmpFailed = false // 探测到内核不回 ICMP 后，本会话走兜底（定期复探）
    @Volatile
    private var echoSinceFail = 0 // 兜底期间收到的 echo 请求计数，用于定期复探内核
    private val pendingEcho = ConcurrentHashMap.newKeySet<String>() // 等待内核应答的 echo 请求键
    private var scheduler: ScheduledExecutorService? = null // 兜底计时器

    // mesh -> VPN 接口（ICMP echo 由应用层兜底应答；其余注入 VPN 接口）
    private val listener = object : Listener {
        override fun onEvent(event: Long, peerID: String, data: ByteArray) {
            when (event) {
                P2p.EventData -> {
                    val dst = ipv4Dst(data)
                    log("VPN 收到 mesh 数据 ${data.size} 字节，目标 ${dst?.let { ipv4Str(it) }}，校验和${if (ipHeaderChecksumValid(data)) "正常" else "异常!"}，IP头 ${hexHeader(data)}")
                    // ICMP echo 应答策略（localStack 未接管时生效；接管则走不到这里）：
                    // 内核优先——注入 tun 等内核代答，500ms 内没读到内核回包就兜底补位；
                    // 兜底期间每 10 个 echo 请求复探一次内核，成功自动切回内核路径。
                    val reply = icmpEchoReply(data)
                    when {
                        reply == null -> injectToTun(data)
                        kernelIcmpFailed -> {
                            echoSinceFail++
                            if (echoSinceFail >= KERNEL_ICMP_REPROBE_EVERY) {
                                echoSinceFail = 0
                                if (injectToTun(data)) {
                                    val key = icmpEchoKey(data, isReply = false)
                                    if (key != null) {
                                        pendingEcho.add(key)
                                        log("兜底中复探内核：已注入 echo request（${KERNEL_ICMP_FALLBACK_MS}ms 窗口）")
                                        scheduleKernelFallback(key, reply)
                                    } else {
                                        sendIcmpReply(reply)
                                    }
                                } else {
                                    sendIcmpReply(reply)
                                }
                            } else {
                                sendIcmpReply(reply)
                            }
                        }
                        else -> {
                            if (injectToTun(data)) {
                                val key = icmpEchoKey(data, isReply = false)
                                if (key != null) {
                                    pendingEcho.add(key)
                                    log("内核优先：已注入 echo request，${KERNEL_ICMP_FALLBACK_MS}ms 无内核应答则兜底")
                                    scheduleKernelFallback(key, reply)
                                } else {
                                    sendIcmpReply(reply)
                                }
                            } else {
                                sendIcmpReply(reply)
                            }
                        }
                    }
                }
                P2p.EventError -> log("错误: ${String(data)}")
                P2p.EventDebug -> log("[打洞] ${String(data)}")
                P2p.EventPeerConnected -> log("节点已连通: $peerID via ${String(data)}")
            }
        }
    }

    // 保护 mesh socket，防止其流量被本 VPN 再路由回去（死循环）
    private val protector = object : SocketProtector {
        override fun protect(fd: Long): Boolean =
            this@MeshVpnService.protect(fd.toInt())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) return START_NOT_STICKY
        when (intent.action) {
            ACTION_STOP -> {
                stopVpn()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val server = intent.getStringExtra("server") ?: return START_NOT_STICKY
                val room = intent.getStringExtra("room") ?: return START_NOT_STICKY
                val token = intent.getStringExtra("token") ?: ""
                val user = intent.getStringExtra("user") ?: ""
                val secret = intent.getStringExtra("secret") ?: ""
                val useLocalStack = intent.getBooleanExtra("localStack", true)
                kernelIcmpFailed = false // 每次启动 VPN 重新探测内核代答能力
                startVpn(server, room, token, user, secret, useLocalStack)
            }
        }
        return START_STICKY
    }

    private fun startVpn(server: String, room: String, token: String, user: String, secret: String, useLocalStack: Boolean) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, buildNotification(),
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, buildNotification())
        }
        val cfg = p2p.Config()
        cfg.serverAddr = server
        cfg.stunAddr = server
        cfg.token = token
        cfg.authUser = user
        cfg.authSecret = secret
        cfg.relayEnabled = true
        cfg.portPrediction = true
        cfg.enableLAN = true
        cfg.debug = true

        if (scheduler == null || scheduler!!.isShutdown) {
            scheduler = Executors.newSingleThreadScheduledExecutor()
        }
        val s = Session(cfg, listener)
        // 先保护 socket，再建 VPN，再连接
        s.setSocketProtector(protector)
        session = s
        running = true

        bridgeThread = Thread {
            try {
                s.connect(room)
                // 等虚拟 IP
                var ip = ""
                var tries = 0
                while (running && ip.isEmpty() && tries < 100) {
                    ip = s.localIP() ?: ""
                    if (ip.isEmpty()) {
                        Thread.sleep(200)
                        tries++
                    }
                }
                if (ip.isEmpty()) {
                    log("未获得虚拟 IP")
                    stopSelf()
                    return@Thread
                }
                // 启用用户态协议栈：发往本机虚拟 IP 的包（ping/TCP）在进程内处理，
                // 不再依赖安卓内核回包。取消勾选时由应用层兜底应答 ICMP（见
                // icmpEchoReply），因为安卓内核不会替 VpnService tun 回包。
                if (useLocalStack) {
                    try {
                        s.enableLocalStack()
                        s.exposeTCP(7000) // 转发到本机 7000 回显服务
                        log("已启用用户态协议栈（本机 IP $ip 的入站流量进程内处理）")
                    } catch (e: Exception) {
                        log("启用用户态协议栈失败: ${e.message}")
                    }
                } else {
                    log("未启用用户态协议栈：ICMP 回包由应用层兜底应答")
                }
                val subnet = s.subnet() ?: "10.9.0.0/24"
                val pfd = buildVpn(ip, subnet)
                if (pfd == null) {
                    log("VPN 建立失败")
                    stopSelf()
                    return@Thread
                }
                this.pfd = pfd
                output = FileOutputStream(pfd.fileDescriptor)
                log("VPN 接口已建立: $ip/$subnet")
                startReadWatchdog()
                bridgeTunToMesh(s, FileInputStream(pfd.fileDescriptor))
            } catch (e: Exception) {
                log("vpn 异常: ${e.message}")
                stopSelf()
            }
        }
        bridgeThread?.start()
    }

    private fun buildVpn(ip: String, subnet: String): ParcelFileDescriptor? {
        val (network, prefix) = parseCidr(subnet)
        // 记录虚拟子网供 bridgeTunToMesh 过滤非虚拟网段流量（此前 virtualNet
        // 从未赋值，过滤失效，可能把非虚拟网段流量打进 mesh）
        virtualNet = parseIpv4(network)
        virtualPrefix = prefix
        val builder = Builder()
            .setSession("p2p-mesh ($ip)")
            .setMtu(1280)
            .setBlocking(true) // 阻塞读：空闲时挂起不耗 CPU；退出靠 stopVpn() 关闭 fd 解除阻塞
            .addAddress(ip, prefix)
            .addRoute(network, prefix)
        // mesh socket 已 protect() 且流量不在虚拟网段，无需禁用本 App 走 VPN，
        // 这样 demo 自身的"自测 ping"和 7000 回显服务也能通过虚拟网互通
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        // Android 12+：子网 VPN 必须声明底层网络，否则 VPN 路由可能不生效
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val nets = cm.allNetworks
            if (nets.isNotEmpty()) {
                builder.setUnderlyingNetworks(nets)
                log("setUnderlyingNetworks 已设置 ${nets.size} 个底层网络")
            } else {
                log("警告: 未获取到任何底层网络（路由可能未安装）")
            }
        } catch (e: Exception) {
            log("setUnderlyingNetworks 失败: ${e.message}")
        }
        return builder.establish()
    }

    // 读循环看门狗：确认读循环存活；多播/广播无回包属正常，只在持续空闲时提示一次
    private fun startReadWatchdog() {
        Thread {
            var warned = false
            while (running) {
                Thread.sleep(5000)
                val idle = (System.currentTimeMillis() - lastReadMs) / 1000
                if (idle > 20) {
                    if (!warned) {
                        log("VPN 读循环空闲 ${idle}s（多播/广播无回包正常；若 ping 单播也无回包才是异常）")
                        warned = true
                    }
                } else {
                    warned = false
                }
            }
        }.start()
    }

    // VPN 接口 -> mesh
    private fun bridgeTunToMesh(s: Session, input: FileInputStream) {
        log("VPN 读循环已启动")
        val buf = ByteArray(65536)
        while (running) {
            val n = try {
                input.read(buf)
            } catch (e: Exception) {
                log("读循环退出: ${e.message}")
                break
            }
            if (n <= 0) break
            lastReadMs = System.currentTimeMillis()
            val pkt = buf.copyOf(n)
            val dst = ipv4Dst(pkt) ?: continue
            val dstIp = ipv4Str(dst)
            val srcIp = ipv4Str(pkt.copyOfRange(12, 16))
            val proto = pkt[9].toInt() and 0xFF
            log("VPN 读取 ${pkt.size} 字节 src=$srcIp dst=$dstIp proto=$proto")
            // 内核优先回 ICMP：读到本机发出的 echo reply 就取消对应请求的兜底计时；
            // 若此前处于兜底状态（复探成功），则切回内核路径
            if (proto == 1) {
                val ihl = (pkt[0].toInt() and 0x0F) * 4
                if (pkt.size >= ihl + 8 && (pkt[ihl].toInt() and 0xFF) == 0) {
                    val key = icmpEchoKey(pkt, isReply = true)
                    if (key != null && pendingEcho.remove(key)) {
                        if (kernelIcmpFailed) {
                            kernelIcmpFailed = false
                            echoSinceFail = 0
                            log("内核已应答 ICMP echo（复探成功，切回内核路径）")
                        } else {
                            log("内核已应答 ICMP echo（取消兜底计时）")
                        }
                    }
                }
            }
            // 非虚拟子网流量丢弃（否则会打进 mesh 导致手机断网）
            val vnet = virtualNet
            if (vnet != null && !inVirtualNet(dst, vnet, virtualPrefix)) {
                log("丢弃非虚拟网段流量: $dstIp")
                continue
            }
            if ((dst[0].toInt() and 0xFF) == 255 || (dst[0].toInt() and 0xFF) >= 224) {
                try { s.broadcast(pkt) } catch (e: Exception) { log("broadcast 失败: ${e.message}") }
            } else {
                try { s.sendToIP(dstIp, pkt) } catch (e: Exception) { log("sendToIP 失败: ${e.message}") }
            }
        }
    }

    private fun stopVpn() {
        running = false
        scheduler?.shutdownNow()
        scheduler = null
        pendingEcho.clear()
        kernelIcmpFailed = false
        echoSinceFail = 0
        session?.disconnect()
        session = null
        try { output?.close() } catch (e: Exception) { }
        try { pfd?.close() } catch (e: Exception) { }
        output = null
        pfd = null
    }

    // 为发往本机虚拟 IP 的 ICMP echo request 构造 echo reply（localStack 未接管
    // 时的兜底）。返回 null 表示该包不是发给本机的 echo 请求，应走正常注入路径。
    private fun icmpEchoReply(pkt: ByteArray): ByteArray? {
        if (pkt.size < 28 || (pkt[0].toInt() shr 4) != 4) return null
        val ihl = (pkt[0].toInt() and 0x0F) * 4
        if (ihl < 20 || pkt.size < ihl + 8) return null
        if ((pkt[9].toInt() and 0xFF) != 1) return null // 只处理 ICMP
        if ((pkt[ihl].toInt() and 0xFF) != 8) return null // 只应答 echo request
        val me = session?.localIP()
        if (me.isNullOrEmpty()) return null
        if (ipv4Str(pkt.copyOfRange(16, 20)) != me) return null // 只应答发给自己的请求
        val reply = pkt.copyOf()
        // 交换源/目的 IP
        for (i in 0..3) {
            reply[12 + i] = pkt[16 + i]
            reply[16 + i] = pkt[12 + i]
        }
        // ICMP type: 8(echo request) -> 0(echo reply)，并重算 ICMP 校验和
        reply[ihl] = 0
        reply[ihl + 2] = 0
        reply[ihl + 3] = 0
        val icmpSum = ipChecksum(reply, ihl, reply.size - ihl)
        reply[ihl + 2] = ((icmpSum shr 8) and 0xFF).toByte()
        reply[ihl + 3] = (icmpSum and 0xFF).toByte()
        // 重算 IP 头校验和
        reply[10] = 0
        reply[11] = 0
        val ipSum = ipChecksum(reply, 0, ihl)
        reply[10] = ((ipSum shr 8) and 0xFF).toByte()
        reply[11] = (ipSum and 0xFF).toByte()
        return reply
    }

    // 把原始 IP 包注入 VPN 接口；返回是否写入成功。
    private fun injectToTun(data: ByteArray): Boolean {
        val out = output ?: return false
        return try {
            out.write(data)
            out.flush()
            log("VPN 已注入接口 ${data.size} 字节")
            true
        } catch (e: Exception) {
            log("VPN 写入失败: ${e.message}")
            false
        }
    }

    // 应用层兜底：把构造好的 echo reply 经 mesh 发回对端。
    private fun sendIcmpReply(reply: ByteArray) {
        val s = session
        if (s == null) {
            log("本地 ICMP 应答跳过：会话已关闭")
            return
        }
        val back = ipv4Str(reply.copyOfRange(16, 20))
        Thread {
            try {
                s.sendToIP(back, reply)
                log("已本地应答 ICMP echo -> $back")
            } catch (e: Exception) {
                log("ICMP 回包发送失败: ${e.message}")
            }
        }.start()
    }

    // echo 请求/回包的匹配键："id:seq:对端IP"（请求取源 IP，回包取目的 IP，两者一致）。
    private fun icmpEchoKey(pkt: ByteArray, isReply: Boolean): String? {
        if (pkt.size < 28 || (pkt[0].toInt() shr 4) != 4) return null
        val ihl = (pkt[0].toInt() and 0x0F) * 4
        if (ihl < 20 || pkt.size < ihl + 8) return null
        val id = ((pkt[ihl + 4].toInt() and 0xFF) shl 8) or (pkt[ihl + 5].toInt() and 0xFF)
        val seq = ((pkt[ihl + 6].toInt() and 0xFF) shl 8) or (pkt[ihl + 7].toInt() and 0xFF)
        val peer = if (isReply) ipv4Str(pkt.copyOfRange(16, 20)) else ipv4Str(pkt.copyOfRange(12, 16))
        return "$id:$seq:$peer"
    }

    // 内核代答等待窗口：超时后若仍未读到内核回包，则兜底补位并置兜底状态
    // （兜底期间每 KERNEL_ICMP_REPROBE_EVERY 个请求复探一次）。
    private fun scheduleKernelFallback(key: String, reply: ByteArray) {
        val sc = scheduler ?: return
        try {
            sc.schedule({
                if (pendingEcho.remove(key)) {
                    val wasFailed = kernelIcmpFailed
                    kernelIcmpFailed = true
                    log(if (wasFailed) {
                        "内核复探仍无应答，继续兜底（${KERNEL_ICMP_REPROBE_EVERY} 个请求后再试）"
                    } else {
                        "内核未在 ${KERNEL_ICMP_FALLBACK_MS}ms 内应答，本会话改用应用层兜底"
                    })
                    sendIcmpReply(reply)
                }
            }, KERNEL_ICMP_FALLBACK_MS, TimeUnit.MILLISECONDS)
        } catch (e: Exception) {
            log("兜底计时器启动失败: ${e.message}")
        }
    }

    private fun buildNotification(): Notification {
        val chId = "p2p-vpn"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(chId, "P2P 组网 VPN", NotificationManager.IMPORTANCE_LOW)
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .createNotificationChannel(ch)
        }
        val pi = PendingIntent.getActivity(this, 0,
            Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, chId)
            .setContentTitle("P2P 组网")
            .setContentText("虚拟局域网运行中")
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setContentIntent(pi)
            .build()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}

private fun parseCidr(cidr: String): Pair<String, Int> {
    val parts = cidr.split("/")
    val prefix = if (parts.size > 1) parts[1].toIntOrNull() ?: 24 else 24
    return parts[0] to prefix
}

private fun parseIpv4(s: String): ByteArray? {
    val parts = s.split(".")
    if (parts.size != 4) return null
    val out = ByteArray(4)
    parts.forEachIndexed { i, p -> out[i] = (p.toIntOrNull() ?: return null).toByte() }
    return out
}

private fun ipv4Dst(pkt: ByteArray): ByteArray? {
    if (pkt.size < 20 || (pkt[0].toInt() shr 4) != 4) return null
    return byteArrayOf(pkt[16], pkt[17], pkt[18], pkt[19])
}

private fun ipv4Str(ip: ByteArray): String =
    ip.joinToString(".") { (it.toInt() and 0xFF).toString() }

// 判断 ip 是否属于网段（仅处理 IPv4 /24 及更小前缀的快速判断）
private fun inVirtualNet(ip: ByteArray, net: ByteArray, prefix: Int): Boolean {
    if (ip.size < 4 || net.size < 4) return false
    val bytes = prefix / 8
    for (i in 0 until bytes) {
        if (ip[i] != net[i]) return false
    }
    if (bytes < 4 && prefix % 8 != 0) {
        val mask = (0xFF shl (8 - prefix % 8)) and 0xFF
        if ((ip[bytes].toInt() and mask) != (net[bytes].toInt() and mask)) return false
    }
    return true
}

// 标准 IP 校验和（RFC 1071）
private fun ipChecksum(data: ByteArray, offset: Int, length: Int): Int {
    var sum = 0
    var i = offset
    val end = offset + length
    while (i < end - 1) {
        sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
        i += 2
    }
    if (i < end) {
        sum += (data[i].toInt() and 0xFF) shl 8
    }
    while (sum > 0xFFFF) {
        sum = (sum and 0xFFFF) + (sum shr 16)
    }
    return (sum.inv()) and 0xFFFF
}

// 校验 IP 头校验和：合法包头（含校验和字段）的补码和为 0
private fun ipHeaderChecksumValid(pkt: ByteArray): Boolean {
    if (pkt.size < 20 || (pkt[0].toInt() shr 4) != 4) return false
    val ihl = (pkt[0].toInt() and 0x0F) * 4
    if (pkt.size < ihl) return false
    return ipChecksum(pkt, 0, ihl) == 0
}

// IP 头前 20 字节的 hex，便于核对 45/协议/源目地址
private fun hexHeader(pkt: ByteArray): String {
    val n = minOf(20, pkt.size)
    return (0 until n).joinToString("") { "%02x".format(pkt[it].toInt() and 0xFF) }
}
