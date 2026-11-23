package com.example.p2pdemo

import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ThreadFactory
import java.util.concurrent.atomic.AtomicInteger

/**
 * 极简 TCP echo 服务，供其它节点通过虚拟 IP:7000 验证入站 TCP 通路。
 * 有明确的生命周期：stop() 会关闭监听 socket、中断 accept 线程并停掉连接线程池。
 */
class TcpEchoServer(
    private val port: Int,
    private val onLog: (String) -> Unit,
) {
    private val lock = Any()
    private val threadIds = AtomicInteger()
    private val connectionExecutor: ExecutorService =
        Executors.newCachedThreadPool(namedFactory("echo-worker"))
    private var serverSocket: ServerSocket? = null
    private var acceptThread: Thread? = null

    val isRunning: Boolean
        get() = synchronized(lock) { serverSocket != null }

    fun start(): Boolean {
        synchronized(lock) {
            if (serverSocket != null) return true
            try {
                val socket = ServerSocket()
                socket.reuseAddress = true
                socket.bind(InetSocketAddress(port))
                serverSocket = socket
                val thread = Thread({ acceptLoop(socket) }, "echo-accept").apply {
                    isDaemon = true
                }
                acceptThread = thread
                thread.start()
                onLog("TCP 回显服务已启动: 端口 $port")
                return true
            } catch (e: Exception) {
                onLog("TCP 回显服务启动失败: ${e.message}")
                return false
            }
        }
    }

    fun stop() {
        val socket: ServerSocket?
        synchronized(lock) {
            socket = serverSocket
            serverSocket = null
            acceptThread?.interrupt()
            acceptThread = null
        }
        try {
            socket?.close()
        } catch (_: Exception) {
            // 已经关闭，忽略。
        }
        connectionExecutor.shutdownNow()
    }

    private fun acceptLoop(socket: ServerSocket) {
        while (!socket.isClosed && !Thread.currentThread().isInterrupted) {
            val client = try {
                socket.accept()
            } catch (_: Exception) {
                if (!socket.isClosed) {
                    onLog("TCP 监听已退出")
                }
                break
            }
            onLog("TCP 收到连接: ${client.inetAddress.hostAddress}")
            connectionExecutor.execute { handle(client) }
        }
    }

    private fun handle(client: Socket) {
        try {
            client.use { socket ->
                val buffer = ByteArray(4096)
                while (!socket.isClosed) {
                    val read = try {
                        socket.getInputStream().read(buffer)
                    } catch (_: Exception) {
                        break
                    }
                    if (read < 0) break
                    if (read == 0) continue
                    socket.getOutputStream().write(buffer, 0, read)
                    socket.getOutputStream().flush()
                }
            }
        } catch (_: Exception) {
            // 对端断开属于正常情况。
        }
    }

    private fun namedFactory(prefix: String): ThreadFactory = ThreadFactory { runnable ->
        Thread(runnable, "$prefix-${threadIds.incrementAndGet()}").apply { isDaemon = true }
    }
}
