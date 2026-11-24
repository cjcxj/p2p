package com.example.p2pdemo

import android.os.ParcelFileDescriptor

/**
 * VpnService 借给组网控制器的能力。
 *
 * 控制器不持有 Android 组件，只有服务实例能调用 `protect()` 和 `establish()`，
 * 所以这两件事通过接口回调完成。服务存活期间注册，销毁时注销。
 */
interface VpnCapability {
    fun protectSocket(fd: Long): Boolean
    fun createTun(vip: String, subnet: String): ParcelFileDescriptor?
}

object VpnBridge {

    /** 与内核接口一致的 MTU。WireGuard 对 IPv4 的最小可用值是 1280。 */
    const val MTU: Int = 1280

    @Volatile
    private var capability: VpnCapability? = null

    val available: Boolean
        get() = capability != null

    fun register(c: VpnCapability) {
        capability = c
    }

    /** 只注销自己，避免服务重启时新实例被旧实例的 onDestroy 摘掉。 */
    fun unregister(c: VpnCapability) {
        if (capability === c) capability = null
    }

    fun protect(fd: Long): Boolean = capability?.protectSocket(fd) ?: false

    /**
     * 建立虚拟网卡并交出裸描述符。返回 -1 表示失败。
     *
     * 返回值一旦有效就归 SDK：`attachTUN` 无论成功失败都会关闭它，
     * 这里再关闭会误伤已被系统复用的编号。
     */
    fun openTunFd(vip: String, subnet: String): Long {
        val pfd = capability?.createTun(vip, subnet) ?: return -1L
        // detachFd 把描述符的所有权交出来，PFD 终结器就不会再关它；
        // 已经交出去的描述符归 SDK，这里绝不能自己再关一次。
        val fd = runCatching { pfd.detachFd() }.getOrDefault(-1)
        if (fd < 0) runCatching { pfd.close() }
        return fd.toLong()
    }
}
