package com.jasonernst.kanonproxy

import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.transport.udp.UdpHeader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.StandardProtocolFamily
import java.nio.ByteBuffer
import java.nio.channels.ByteChannel
import java.nio.channels.DatagramChannel
import java.nio.channels.SocketChannel
import java.util.concurrent.LinkedBlockingDeque

class Session(
    val sourceIp: InetAddress,
    val sourcePort: UShort,
    val destinationIp: InetAddress,
    val destinationPort: UShort,
    val protocol: UByte,
    val returnQueue: LinkedBlockingDeque<Packet>,
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    val channel: ByteChannel =
        if (protocol == IpType.UDP.value) {
            if (destinationIp is Inet4Address) {
                DatagramChannel.open(StandardProtocolFamily.INET)
            } else {
                DatagramChannel.open(StandardProtocolFamily.INET6)
            }
        } else if (protocol == IpType.TCP.value) {
            if (destinationIp is Inet4Address) {
                SocketChannel.open(StandardProtocolFamily.INET)
            } else {
                SocketChannel.open(StandardProtocolFamily.INET6)
            }
        } else {
            throw IllegalArgumentException("Unsupported protocol: $protocol")
        }
    private val readBuffer = ByteBuffer.allocate(DEFAULT_BUFFER_SIZE)

    init {
        CoroutineScope(Dispatchers.IO).launch {
            if (channel is SocketChannel) {
                channel.connect(InetSocketAddress(destinationIp, destinationPort.toInt()))
            } else {
                (channel as DatagramChannel).connect(InetSocketAddress(destinationIp, destinationPort.toInt()))
            }
            handleReturnTraffic()
        }
    }

    companion object {
        fun getKey(
            sourceIp: InetAddress,
            sourcePort: UShort,
            destinationIp: InetAddress,
            destinationPort: UShort,
            protocol: UByte,
        ): String = "$sourceIp:$sourcePort:$destinationIp:$destinationPort:$protocol"
    }

    fun getKey(): String = getKey(sourceIp, sourcePort, destinationIp, destinationPort, protocol)

    override fun toString(): String =
        "Session(sourceIp='$sourceIp', sourcePort=$sourcePort, destinationIp='$destinationIp', destinationPort=$destinationPort, protocol=$protocol)"

    suspend fun handleReturnTraffic() {
        while (channel.isOpen) {
            logger.debug("Waiting for return traffic on $this")
            val len = channel.read(readBuffer)
            if (len == -1) {
                logger.error("Channel closed")
                break
            }
            if (len > 0) {
                readBuffer.flip()
                val payload = ByteArray(len)
                readBuffer.get(payload, 0, len)

                val udpHeader = UdpHeader(destinationPort, sourcePort, len.toUShort(), 0u)
                val ipHeader =
                    if (sourceIp is Inet4Address) {
                        Ipv4Header(
                            sourceAddress = destinationIp,
                            destinationAddress = sourceIp,
                            protocol = IpType.UDP.value,
                            totalLength =
                                (
                                    Ipv4Header.IP4_MIN_HEADER_LENGTH +
                                        udpHeader.totalLength +
                                        len.toUShort()
                                ).toUShort(),
                        )
                    } else {
                        Ipv6Header(
                            sourceAddress = destinationIp,
                            destinationAddress = sourceIp,
                            protocol = IpType.UDP.value,
                            payloadLength = (40u + udpHeader.totalLength).toUShort(),
                        )
                    }
                val packet = Packet(ipHeader, udpHeader, payload)
                returnQueue.put(packet)
                logger.debug("Read $len bytes from $channel")
                readBuffer.clear()
            }
        }
    }
}
