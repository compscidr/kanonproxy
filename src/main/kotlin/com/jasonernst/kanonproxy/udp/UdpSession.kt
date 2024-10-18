package com.jasonernst.kanonproxy.udp

import com.jasonernst.kanonproxy.Session
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
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.StandardProtocolFamily
import java.nio.channels.DatagramChannel
import java.util.concurrent.LinkedBlockingDeque

class UdpSession(
    sourceAddress: InetAddress,
    sourcePort: UShort,
    destinationAddress: InetAddress,
    destinationPort: UShort,
    returnQueue: LinkedBlockingDeque<Packet>,
) : Session(
        sourceAddress = sourceAddress,
        sourcePort = sourcePort,
        destinationAddress = destinationAddress,
        destinationPort = destinationPort,
        protocol = IpType.UDP.value,
        returnQueue = returnQueue,
    ) {
    private val logger = LoggerFactory.getLogger(javaClass)

    override val channel: DatagramChannel =
        if (destinationAddress is Inet4Address) {
            DatagramChannel.open(StandardProtocolFamily.INET)
        } else {
            DatagramChannel.open(StandardProtocolFamily.INET6)
        }

    init {
        logger.debug("UDP connecting to {}:{}", destinationAddress, destinationPort)
        channel.connect(InetSocketAddress(destinationAddress, destinationPort.toInt()))
        logger.debug("UDP Connected")
        CoroutineScope(Dispatchers.IO).launch {
            handleReturnTraffic()
        }
    }

    override fun handlePayloadFromInternet(payload: ByteArray) {
        val udpHeader = UdpHeader(destinationPort, sourcePort, payload.size.toUShort(), 0u)
        val ipHeader =
            if (sourceAddress is Inet4Address) {
                Ipv4Header(
                    sourceAddress = destinationAddress as Inet4Address,
                    destinationAddress = sourceAddress,
                    protocol = IpType.UDP.value,
                    totalLength =
                        (
                            Ipv4Header.IP4_MIN_HEADER_LENGTH +
                                udpHeader.totalLength +
                                payload.size.toUShort()
                        ).toUShort(),
                )
            } else {
                Ipv6Header(
                    sourceAddress = destinationAddress as Inet6Address,
                    destinationAddress = sourceAddress as Inet6Address,
                    protocol = IpType.UDP.value,
                    payloadLength = (40u + udpHeader.totalLength).toUShort(),
                )
            }
        val packet = Packet(ipHeader, udpHeader, payload)
        returnQueue.put(packet)
    }
}
