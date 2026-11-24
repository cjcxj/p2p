package com.example.p2pdemo

import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit

/**
 * 虚拟网卡的连通性自测。
 *
 * 不用 `InetAddress.isReachable`：它在 Android 上既不保证发 ICMP，也会因为
 * 本应用 socket 未走隧道而给出假阴性。这里直接调用系统 ping，并另做一个
 * TCP 回声往返，两者都真正经过隧道。
 */
object NetTools {

    data class PingResult(
        val reachable: Boolean,
        val transmitted: Int,
        val received: Int,
        val lossPercent: Double,
        val avgMs: Double,
        val detail: String,
    )

    data class EchoResult(
        val ok: Boolean,
        val rttMs: Long,
        val reply: String,
        val error: String,
    )

    private val RTT_PATTERN = Regex("""=\s*([\d.]+)/([\d.]+)/([\d.]+)/""")
    private val STATS_PATTERN = Regex("""(\d+)\s+packets transmitted,\s+(\d+)\s+received""")

    fun ping(host: String, count: Int = 4, deadlineSec: Int = 4): PingResult {
        if (host.isBlank()) {
            return PingResult(false, 0, 0, 100.0, 0.0, "没有目标地址")
        }
        val process = try {
            ProcessBuilder(
                "/system/bin/ping",
                "-c", count.toString(),
                "-w", deadlineSec.toString(),
                host,
            ).redirectErrorStream(true).start()
        } catch (e: Exception) {
            return PingResult(false, 0, 0, 100.0, 0.0, "无法执行 ping: ${e.message}")
        }
        val output = process.inputStream.bufferedReader().use { it.readText() }
        val finished = process.waitFor(deadlineSec + 4L, TimeUnit.SECONDS)
        if (!finished) {
            process.destroy()
            return PingResult(false, count, 0, 100.0, 0.0, "ping 超时未退出")
        }
        val stats = STATS_PATTERN.find(output)
        val transmitted = stats?.groupValues?.get(1)?.toIntOrNull() ?: count
        val received = stats?.groupValues?.get(2)?.toIntOrNull() ?: 0
        val rtt = RTT_PATTERN.find(output)?.groupValues?.get(2)?.toDoubleOrNull() ?: 0.0
        val loss = if (transmitted == 0) 100.0 else (transmitted - received) * 100.0 / transmitted
        return PingResult(
            reachable = received > 0,
            transmitted = transmitted,
            received = received,
            lossPercent = loss,
            avgMs = rtt,
            detail = if (received > 0) {
                "应答 $received/$transmitted，平均 ${fmt(rtt)} ms"
            } else {
                firstErrorLine(output) ?: "无应答（虚拟网卡未开启或路由未到对端）"
            },
        )
    }

    /** 对端节点的 TCP 回声端口往返；同时验证入站通路是否被隧道放行。 */
    fun tcpEcho(host: String, port: Int, payload: String, timeoutMs: Int = 4000): EchoResult {
        if (host.isBlank()) return EchoResult(false, 0, "", "没有目标地址")
        val socket = Socket()
        val start = System.nanoTime()
        return try {
            socket.soTimeout = timeoutMs
            socket.connect(InetSocketAddress(host, port), timeoutMs)
            socket.getOutputStream().write(payload.toByteArray(Charsets.UTF_8))
            socket.getOutputStream().flush()
            val buffer = ByteArray(payload.toByteArray(Charsets.UTF_8).size.coerceAtLeast(1))
            var read = 0
            while (read < buffer.size) {
                val n = socket.inputStream.read(buffer, read, buffer.size - read)
                if (n < 0) break
                read += n
            }
            val rtt = (System.nanoTime() - start) / 1_000_000
            EchoResult(
                ok = read > 0,
                rttMs = rtt,
                reply = String(buffer, 0, read, Charsets.UTF_8),
                error = "",
            )
        } catch (e: Exception) {
            val rtt = (System.nanoTime() - start) / 1_000_000
            EchoResult(false, rtt, "", e.javaClass.simpleName + ": " + (e.message ?: ""))
        } finally {
            try {
                socket.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun fmt(value: Double): String = String.format("%.1f", value)

    private fun firstErrorLine(output: String): String? =
        output.lineSequence()
            .map { it.trim() }
            .firstOrNull { it.isNotEmpty() && (it.contains("fail") || it.contains("unreachable") || it.contains("error")) }
}
