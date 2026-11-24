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

/**
 * 虚拟网卡的宿主。
 *
 * 这个服务不再建会话：会话归 [MeshController]，一台设备只有一个房间身份。
 * 服务只提供 Android 才有的两件事——把 UDP socket 摘出隧道、用 [Builder] 造一个
 * tun 描述符——然后交给 SDK 直接跑 WireGuard。逐包 Kotlin 桥接（tun 读循环、
 * sendToIP 转发、应用层 ICMP 代答）已经删掉，那是旧数据面最慢的一段。
 *
 * 因此本机流量也归内核：ping 由内核应答，TCP 7000 只要在本机监听就能从虚拟网访问。
 */
class MeshVpnService : VpnService(), VpnCapability {

    override fun onCreate() {
        super.onCreate()
        VpnBridge.register(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) return START_NOT_STICKY
        return when (intent.action) {
            ACTION_STOP -> {
                log("收到停止请求")
                meshController(this).setTunnel(false)
                stopSelf()
                START_NOT_STICKY
            }
            ACTION_START -> {
                if (!bringUpForeground()) {
                    stopSelf()
                    return START_NOT_STICKY
                }
                // 连房间和挂网卡都由控制器完成，它才知道现在用的是哪一个会话。
                meshController(this).startAll()
                START_STICKY
            }
            else -> START_NOT_STICKY
        }
    }

    override fun onDestroy() {
        VpnBridge.unregister(this)
        // 进程还在，会话可以留着；但描述符随服务销毁失效，必须先把隧道状态归零。
        runCatching { meshController(this).setTunnel(false) }
        log("VPN 服务已销毁")
        super.onDestroy()
    }

    // ---------- VpnCapability ----------

    override fun protectSocket(fd: Long): Boolean = protect(fd.toInt())

    override fun createTun(vip: String, subnet: String): ParcelFileDescriptor? {
        val network = subnet.substringBefore('/')
        val prefix = subnet.substringAfter('/', DEFAULT_PREFIX.toString())
            .toIntOrNull()
            ?.coerceIn(0, 32)
            ?: DEFAULT_PREFIX

        val builder = Builder()
            .setSession("p2p-mesh")
            .setMtu(VpnBridge.MTU)
            .addAddress(vip, prefix)
            .addRoute(network, prefix)

        bindUnderlyingNetworks(builder)

        return try {
            builder.establish()
        } catch (e: Exception) {
            log("建立 VPN 接口异常: ${e.message}")
            null
        }
    }

    // ---------- 辅助 ----------

    private fun bringUpForeground(): Boolean {
        return try {
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
            true
        } catch (e: Exception) {
            log("前台服务启动失败: ${e.message}")
            false
        }
    }

    /**
     * 不绑底层网络时，默认路由会被 VPN 接管，打洞用的 UDP socket 若没 protect 成功
     * 就彻底出不去。绑上物理网络后，被 protect 的 socket 仍能正常直达公网。
     */
    private fun bindUnderlyingNetworks(builder: Builder) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
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

    private fun buildNotification(): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "P2P 组网", NotificationManager.IMPORTANCE_LOW)
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
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("P2P 组网")
            .setContentText("虚拟网卡运行中")
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setOngoing(true)
            .setContentIntent(contentIntent)
            .addAction(0, "断开", stopIntent)
            .build()
    }

    private fun log(message: String) {
        Log.i(TAG, message)
        runCatching { meshController(this).appendExternalLog(message) }
    }

    companion object {
        const val ACTION_START = "com.example.p2pdemo.VPN_START"
        const val ACTION_STOP = "com.example.p2pdemo.VPN_STOP"

        private const val TAG = "MeshVpn"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "p2p-vpn"
        private const val DEFAULT_PREFIX = 24

        fun start(context: Context) {
            val intent = Intent(context, MeshVpnService::class.java).setAction(ACTION_START)
            try {
                context.startForegroundService(intent)
            } catch (e: Exception) {
                Log.e(TAG, "启动 VPN 服务失败: ${e.message}")
            }
        }

        fun stop(context: Context) {
            runCatching { context.stopService(Intent(context, MeshVpnService::class.java)) }
        }
    }
}
