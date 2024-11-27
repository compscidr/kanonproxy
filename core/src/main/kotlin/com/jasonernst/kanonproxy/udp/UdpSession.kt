package com.jasonernst.kanonproxy.udp

import com.jasonernst.kanonproxy.Session
import com.jasonernst.kanonproxy.SessionManager
import com.jasonernst.kanonproxy.VpnProtector
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.transport.TransportHeader
import com.jasonernst.knet.transport.udp.UdpHeader
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.StandardProtocolFamily
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey.OP_READ
import java.util.concurrent.LinkedBlockingDeque

class UdpSession(
    initialIpHeader: IpHeader,
    initialTransportHeader: TransportHeader,
    initialPayload: ByteArray,
    returnQueue: LinkedBlockingDeque<Packet>,
    protector: VpnProtector,
    sessionManager: SessionManager,
    clientAddress: InetSocketAddress,
) : Session(
        initialIpHeader = initialIpHeader,
        initialTransportHeader = initialTransportHeader,
        initialPayload = initialPayload,
        returnQueue = returnQueue,
        protector = protector,
        sessionManager = sessionManager,
        clientAddress = clientAddress,
    ) {
    private val logger = LoggerFactory.getLogger(javaClass)

    override val channel: DatagramChannel =
        if (initialIpHeader.destinationAddress is Inet4Address) {
            DatagramChannel.open(StandardProtocolFamily.INET)
        } else {
            DatagramChannel.open(StandardProtocolFamily.INET6)
        }

    init {
        startSelector()
        outgoingScope.launch {
            try {
                logger.debug("UDP connecting to {}:{}", initialIpHeader.destinationAddress, initialTransportHeader.destinationPort)
                protector.protectUDPSocket(channel.socket())
                channel.configureBlocking(false)
                channel.register(selector, OP_READ)
                channel.connect(InetSocketAddress(initialIpHeader.destinationAddress, initialTransportHeader.destinationPort.toInt()))
                logger.debug("UDP Connected")
                startIncomingHandling()
            } catch (e: Exception) {
                handleExceptionOnRemoteChannel(e)
            }
        }
    }

    override fun read() {
        var closed = false
        try {
            val len = handleReturnTrafficLoop(readBuffer.capacity())
            if (len < 0) {
                closed = true
            }
        } catch (e: Exception) {
            closed = true
        }
        if (closed) {
            logger.warn("Remote Udp channel closed")
        }
    }

    override fun handlePayloadFromInternet(payload: ByteArray) {
        if (initialIpHeader == null || initialTransportHeader == null) {
            logger.error("Initial headers are null, can't send return UDP traffic")
            return
        }
        val udpHeader =
            UdpHeader(
                initialTransportHeader!!.destinationPort,
                initialTransportHeader!!.sourcePort,
                (
                    payload.size.toUShort() +
                        UdpHeader.UDP_HEADER_LENGTH
                ).toUShort(),
                0u,
            )
        val ipHeader =
            if (initialIpHeader!!.sourceAddress is Inet4Address) {
                Ipv4Header(
                    sourceAddress = initialIpHeader!!.destinationAddress as Inet4Address,
                    destinationAddress = initialIpHeader!!.sourceAddress as Inet4Address,
                    protocol = IpType.UDP.value,
                    totalLength = (Ipv4Header.IP4_MIN_HEADER_LENGTH + udpHeader.totalLength).toUShort(),
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
            val buffer = ByteBuffer.wrap(payload)
            while (buffer.hasRemaining()) {
                outgoingToInternet.write(buffer)
            }
            readyToWrite()
        } catch (e: Exception) {
            logger.error("Error writing to UDP channel: $e")
            close()
        }
    }
}
