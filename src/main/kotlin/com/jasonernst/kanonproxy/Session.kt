package com.jasonernst.kanonproxy

import com.jasonernst.kanonproxy.tcp.AnonymousTcpSession
import com.jasonernst.kanonproxy.udp.UdpSession
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpType
import org.slf4j.LoggerFactory
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.channels.ByteChannel
import java.util.concurrent.LinkedBlockingDeque

abstract class Session(
    val sourceAddress: InetAddress,
    val sourcePort: UShort,
    val destinationAddress: InetAddress,
    val destinationPort: UShort,
    val protocol: UByte,
    val returnQueue: LinkedBlockingDeque<Packet>,
    val protector: VpnProtector
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    abstract val channel: ByteChannel
    private val readBuffer = ByteBuffer.allocate(DEFAULT_BUFFER_SIZE)

    companion object {
        fun getKey(
            sourceIp: InetAddress,
            sourcePort: UShort,
            destinationIp: InetAddress,
            destinationPort: UShort,
            protocol: UByte,
        ): String = "$sourceIp:$sourcePort:$destinationIp:$destinationPort:$protocol"

        /**
         * Depending on the protocol, returns either a UDP or TCP session
         */
        fun getSession(
            sourceIp: InetAddress,
            sourcePort: UShort,
            destinationIp: InetAddress,
            destinationPort: UShort,
            protocol: UByte,
            returnQueue: LinkedBlockingDeque<Packet>,
            protector: VpnProtector
        ): Session =
            when (protocol) {
                IpType.UDP.value -> {
                    UdpSession(sourceIp, sourcePort, destinationIp, destinationPort, returnQueue, protector)
                }
                IpType.TCP.value -> {
                    AnonymousTcpSession(sourceIp, sourcePort, destinationIp, destinationPort, returnQueue, protector)
                }
                else -> {
                    throw IllegalArgumentException("Unsupported protocol for session")
                }
            }
    }

    fun getKey(): String = getKey(sourceAddress, sourcePort, destinationAddress, destinationPort, protocol)

    override fun toString(): String =
        "Session(sourceAddress='$sourceAddress', sourcePort=$sourcePort, destinationAddress='$destinationAddress', destinationPort=$destinationPort, protocol=$protocol)"

    fun handleReturnTraffic() {
        while (channel.isOpen) {
            logger.debug("Waiting for return traffic on {}", this)
            val len = channel.read(readBuffer)
            if (len == -1) {
                logger.error("Channel closed")
                break
            }
            if (len > 0) {
                readBuffer.flip()
                val payload = ByteArray(len)
                readBuffer.get(payload, 0, len)
                handlePayloadFromInternet(payload)
                logger.debug("Read {} bytes from {}", len, channel)
                readBuffer.clear()
            }
        }
    }

    abstract fun handlePayloadFromInternet(payload: ByteArray)
}
