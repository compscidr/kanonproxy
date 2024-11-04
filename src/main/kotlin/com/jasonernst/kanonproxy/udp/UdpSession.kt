package com.jasonernst.kanonproxy.udp

import com.jasonernst.icmp.common.v4.IcmpV4DestinationUnreachableCodes
import com.jasonernst.icmp.common.v6.IcmpV6DestinationUnreachableCodes
import com.jasonernst.kanonproxy.Session
import com.jasonernst.kanonproxy.SessionManager
import com.jasonernst.kanonproxy.VpnProtector
import com.jasonernst.kanonproxy.icmp.IcmpFactory
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.transport.TransportHeader
import com.jasonernst.knet.transport.tcp.options.TcpOptionMaximumSegmentSize
import com.jasonernst.knet.transport.udp.UdpHeader
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.StandardProtocolFamily
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.util.concurrent.LinkedBlockingDeque

class UdpSession(
    initialIpHeader: IpHeader,
    initialTransportHeader: TransportHeader,
    initialPayload: ByteArray,
    returnQueue: LinkedBlockingDeque<Packet>,
    protector: VpnProtector,
    sessionManager: SessionManager,
) : Session(
        initialIpHeader = initialIpHeader,
        initialTransportHeader = initialTransportHeader,
        initialPayload = initialPayload,
        returnQueue = returnQueue,
        protector = protector,
        sessionManager = sessionManager,
    ) {
    private val logger = LoggerFactory.getLogger(javaClass)

    override val channel: DatagramChannel =
        if (initialIpHeader.destinationAddress is Inet4Address) {
            DatagramChannel.open(StandardProtocolFamily.INET)
        } else {
            DatagramChannel.open(StandardProtocolFamily.INET6)
        }

    init {
        outgoingScope.launch {
            try {
                logger.debug("UDP connecting to {}:{}", initialIpHeader.destinationAddress, initialTransportHeader.destinationPort)
                protector.protectUDPSocket(channel.socket())
                channel.connect(InetSocketAddress(initialIpHeader.destinationAddress, initialTransportHeader.destinationPort.toInt()))
                logger.debug("UDP Connected")
                startIncomingHandling()
            } catch (e: Exception) {
                logger.error("Error creating UDP session: ${e.message}")
                val code =
                    when (initialIpHeader.sourceAddress) {
                        is Inet4Address -> IcmpV4DestinationUnreachableCodes.HOST_UNREACHABLE
                        else -> IcmpV6DestinationUnreachableCodes.ADDRESS_UNREACHABLE
                    }
                val mtu =
                    if (initialIpHeader.sourceAddress is Inet4Address) {
                        TcpOptionMaximumSegmentSize.defaultIpv4MSS
                    } else {
                        TcpOptionMaximumSegmentSize.defaultIpv6MSS
                    }
                val response =
                    IcmpFactory.createDestinationUnreachable(
                        code,
                        // source address for the Icmp header, send it back to the client as if its the clients own OS
                        // telling it that its unreachable
                        initialIpHeader.sourceAddress,
                        initialIpHeader,
                        initialTransportHeader,
                        initialPayload,
                        mtu.toInt(),
                    )
                returnQueue.add(response)
            }

            try {
                logger.debug("UDP session listening for remote responses")
                do {
                    val len = handleReturnTrafficLoop()
                } while (channel.isOpen && len > -1)
            } catch (e: Exception) {
                logger.warn("Remote Udp channel closed")
            }
            logger.debug("UDP session no longer listening for remote responses")
        }
    }

    override fun handlePayloadFromInternet(payload: ByteArray) {
        if (initialIpHeader == null || initialTransportHeader == null) {
            logger.error("Initial headers are null, can't send return UDP traffic")
            return
        }
        val udpHeader =
            UdpHeader(initialTransportHeader!!.destinationPort, initialTransportHeader!!.sourcePort, payload.size.toUShort(), 0u)
        val ipHeader =
            if (initialIpHeader!!.sourceAddress is Inet4Address) {
                Ipv4Header(
                    sourceAddress = initialIpHeader!!.destinationAddress as Inet4Address,
                    destinationAddress = initialIpHeader!!.sourceAddress as Inet4Address,
                    protocol = IpType.UDP.value,
                    totalLength = (Ipv4Header.IP4_MIN_HEADER_LENGTH + UdpHeader.UDP_HEADER_LENGTH + udpHeader.totalLength).toUShort(),
                )
            } else {
                Ipv6Header(
                    sourceAddress = initialIpHeader!!.destinationAddress as Inet6Address,
                    destinationAddress = initialIpHeader!!.sourceAddress as Inet6Address,
                    protocol = IpType.UDP.value,
                    payloadLength = (Ipv6Header.IP6_HEADER_SIZE + UdpHeader.UDP_HEADER_LENGTH + udpHeader.totalLength).toUShort(),
                )
            }
        val packet = Packet(ipHeader, udpHeader, payload)
        returnQueue.put(packet)
    }

    override fun handlePacketFromClient(packet: Packet) {
        val payload = packet.payload
        try {
            val bytesWrote = channel.write(ByteBuffer.wrap(payload))
            logger.debug("Wrote {} bytes to session {}", bytesWrote, this)
        } catch (e: Exception) {
            logger.error("Error writing to UDP channel: $e")
            close()
        }
    }
}
