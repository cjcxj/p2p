package com.example.p2pdemo

import android.content.Context
import android.content.Intent

/**
 * 应用内部广播：VPN 服务运行在同一个进程里，但通过广播把日志和状态送到 UI，
 * Activity 重建后也能继续收到消息，比静态 logHook 更不容易泄漏。
 */
object AppBus {

    const val ACTION_LOG = "com.example.p2pdemo.action.LOG"
    const val ACTION_VPN_STATE = "com.example.p2pdemo.action.VPN_STATE"
    const val EXTRA_MESSAGE = "extra.message"
    const val EXTRA_RUNNING = "extra.running"

    fun sendLog(context: Context, message: String) {
        context.sendBroadcast(
            Intent(ACTION_LOG)
                .setPackage(context.packageName)
                .putExtra(EXTRA_MESSAGE, message)
        )
    }

    fun sendVpnState(context: Context, running: Boolean) {
        context.sendBroadcast(
            Intent(ACTION_VPN_STATE)
                .setPackage(context.packageName)
                .putExtra(EXTRA_RUNNING, running)
        )
    }
}
