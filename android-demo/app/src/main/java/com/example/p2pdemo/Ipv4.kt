package com.example.p2pdemo

/**
 * 演示所需的少量 IPv4 工具，全部是纯函数，方便单独测试和阅读。
 * 只处理 demo 需要的场景：IPv4 头解析、子网判断、广播识别、ICMP echo 代答。
 */
object Ipv4 {

    const val MIN_HEADER_LENGTH = 20
    const val ICMP_PROTOCOL = 1
    const val ICMP_ECHO_REQUEST = 8

    data class Packet(
        val headerLength: Int,
        val protocol: Int,
        val source: String,
        val destination: String,
        val destinationBytes: ByteArray,
        val totalLength: Int,
    )

    /** 解析 IPv4 头。包长度不足、版本不对或声明长度不合理时返回 null。 */
    fun parse(raw: ByteArray): Packet? {
        if (raw.size < MIN_HEADER_LENGTH) return null
        if ((raw[0].toInt() ushr 4) != 4) return null

        val headerLength = (raw[0].toInt() and 0x0F) * 4
        if (headerLength < MIN_HEADER_LENGTH || raw.size < headerLength) return null

        val totalLength = ((raw[2].toInt() and 0xFF) shl 8) or (raw[3].toInt() and 0xFF)
        if (totalLength < headerLength || totalLength > raw.size) return null

        val destinationBytes = byteArrayOf(raw[16], raw[17], raw[18], raw[19])
        return Packet(
            headerLength = headerLength,
            protocol = raw[9].toInt() and 0xFF,
            source = bytesToString(byteArrayOf(raw[12], raw[13], raw[14], raw[15])),
            destination = bytesToString(destinationBytes),
            destinationBytes = destinationBytes,
            totalLength = totalLength,
        )
    }

    /** "10.9.0.2" -> ByteArray(4)，非法输入返回 null。 */
    fun parseAddress(text: String): ByteArray? {
        val parts = text.split(".")
        if (parts.size != 4) return null
        val out = ByteArray(4)
        parts.forEachIndexed { index, part ->
            val value = part.toIntOrNull() ?: return null
            if (value !in 0..255) return null
            out[index] = value.toByte()
        }
        return out
    }

    fun bytesToString(bytes: ByteArray): String =
        bytes.joinToString(".") { (it.toInt() and 0xFF).toString() }

    /** 判断地址是否属于 network/prefix 网段，支持任意 0..32 前缀长度。 */
    fun inSubnet(address: ByteArray, network: ByteArray, prefix: Int): Boolean {
        if (address.size < 4 || network.size < 4 || prefix !in 0..32) return false
        val fullBytes = prefix / 8
        for (i in 0 until fullBytes) {
            if (address[i] != network[i]) return false
        }
        val remainingBits = prefix % 8
        if (fullBytes < 4 && remainingBits > 0) {
            val mask = (0xFF shl (8 - remainingBits)) and 0xFF
            if ((address[fullBytes].toInt() and mask) != (network[fullBytes].toInt() and mask)) {
                return false
            }
        }
        return true
    }

    /** 子网定向广播地址（如 10.9.0.255 / 10.9.0.0/24）。 */
    fun isSubnetBroadcast(address: ByteArray, network: ByteArray, prefix: Int): Boolean {
        if (address.size != 4 || network.size != 4 || prefix !in 0..32) return false
        if (!inSubnet(address, network, prefix)) return false
        val hostBits = 32 - prefix
        if (hostBits == 0) return false
        val hostMask = (1L shl hostBits) - 1
        return (toLong(address) and hostMask) == hostMask
    }

    fun isLimitedBroadcast(address: ByteArray): Boolean =
        address.size == 4 && address.all { (it.toInt() and 0xFF) == 255 }

    fun isMulticast(address: ByteArray): Boolean =
        address.size == 4 && ((address[0].toInt() and 0xFF) in 224..239)

    /** 是否为 ICMP echo reply（type=0）。 */
    fun isIcmpEchoReply(raw: ByteArray): Boolean {
        val packet = parse(raw) ?: return false
        if (packet.protocol != ICMP_PROTOCOL || packet.totalLength < packet.headerLength + 8) return false
        return (raw[packet.headerLength].toInt() and 0xFF) == 0
    }

    /**
     * 生成用于匹配 ICMP echo request/reply 的 key。
     * 使用 id、seq 以及排序后的源/目的地址，因此 request 和 reply 能对应上。
     */
    fun icmpEchoKey(raw: ByteArray): String? {
        val packet = parse(raw) ?: return null
        if (packet.protocol != ICMP_PROTOCOL || packet.totalLength < packet.headerLength + 8) return null
        val offset = packet.headerLength
        val type = raw[offset].toInt() and 0xFF
        if (type != ICMP_ECHO_REQUEST && type != 0) return null
        val id = ((raw[offset + 4].toInt() and 0xFF) shl 8) or (raw[offset + 5].toInt() and 0xFF)
        val seq = ((raw[offset + 6].toInt() and 0xFF) shl 8) or (raw[offset + 7].toInt() and 0xFF)
        val addrs = listOf(packet.source, packet.destination).sorted()
        return "$id:$seq:${addrs[0]}|${addrs[1]}"
    }

    /**
     * 为发给 localIp 的 ICMP echo request 构造 echo reply。
     * 返回 null 表示该包不是发给本机的 echo request，应走其它处理路径。
     */
    fun icmpEchoReply(raw: ByteArray, localIp: String): ByteArray? {
        val packet = parse(raw) ?: return null
        if (packet.protocol != ICMP_PROTOCOL || packet.destination != localIp) return null

        val offset = packet.headerLength
        if (packet.totalLength < offset + 8) return null
        if ((raw[offset].toInt() and 0xFF) != ICMP_ECHO_REQUEST) return null

        val reply = raw.copyOf(packet.totalLength)

        // 交换源 / 目的地址。
        raw.copyInto(reply, 12, 16, 20)
        raw.copyInto(reply, 16, 12, 16)

        // ICMP type: echo request -> echo reply。
        reply[offset] = 0

        // 重算 ICMP 校验和。
        reply[offset + 2] = 0
        reply[offset + 3] = 0
        val icmpSum = checksum(reply, offset, packet.totalLength - offset)
        reply[offset + 2] = ((icmpSum shr 8) and 0xFF).toByte()
        reply[offset + 3] = (icmpSum and 0xFF).toByte()

        // 重算 IP 头校验和。
        reply[10] = 0
        reply[11] = 0
        val ipSum = checksum(reply, 0, packet.headerLength)
        reply[10] = ((ipSum shr 8) and 0xFF).toByte()
        reply[11] = (ipSum and 0xFF).toByte()

        return reply
    }

    /** RFC 1071 校验和。 */
    fun checksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while (sum ushr 16 > 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv().toInt() and 0xFFFF
    }

    private fun toLong(bytes: ByteArray): Long {
        var value = 0L
        for (b in bytes) {
            value = (value shl 8) or (b.toLong() and 0xFF)
        }
        return value
    }
}
