package com.jasonernst.kanonproxy.udp

import com.jasonernst.kanonproxy.ChangeRequest
import com.jasonernst.kanonproxy.Session
import com.jasonernst.kanonproxy.SessionManager
import com.jasonernst.kanonproxy.TrafficAccounting
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
import java.nio.channels.SelectionKey.OP_WRITE
import java.util.concurrent.LinkedBlockingDeque

class UdpSession(
    initialIpHeader: IpHeader,
    initialTransportHeader: TransportHeader,
    initialPayload: ByteArray,
    returnQueue: LinkedBlockingDeque<Packet>,
    protector: VpnProtector,
    sessionManager: SessionManager,
    clientAddress: InetSocketAddress,
    trafficAccounting: TrafficAccounting,
) : Session(
        initialIpHeader = initialIpHeader,
        initialTransportHeader = initialTransportHeader,
        initialPayload = initialPayload,
        returnQueue = returnQueue,
        protector = protector,
        sessionManager = sessionManager,
        clientAddress = clientAddress,
        trafficAccounting = trafficAccounting,
    ) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private var acceptedBytes = 0u

    override val channel: DatagramChannel =
        if (initialIpHeader.destinationAddress is Inet4Address) {
            DatagramChannel.open(StandardProtocolFamily.INET)
        } else {
            DatagramChannel.open(StandardProtocolFamily.INET6)
        }

    init {
        startSelector()
        outgoingScope.launch {
            if (isRunning.get().not()) {
                logger.debug("Session shutting down before starting")
                return@launch
            }
            Thread.currentThread().name = "Outgoing handler: ${getKey()}"
            try {
                // logger.debug("UDP connecting to {}:{}", initialIpHeader.destinationAddress, initialTransportHeader.destinationPort)
                protector.protectUDPSocket(channel.socket())
                channel.socket().soTimeout = 0
                channel.configureBlocking(false)
                channel.connect(InetSocketAddress(initialIpHeader.destinationAddress, initialTransportHeader.destinationPort.toInt()))
                // logger.debug("UDP Connected")
                isConnecting.set(false)
                synchronized(changeRequests) {
                    // logger.debug("Registering for WRITE")
                    changeRequests.add(ChangeRequest(channel, ChangeRequest.REGISTER, OP_WRITE))
                }
                startIncomingHandling()
            } catch (e: Exception) {
                logger.error("ERROR ON UDP CONNECT $e")
                handleExceptionOnRemoteChannel(e)
            }
            outgoingJob.complete()
        }
    }

    override fun read(): Boolean {
        var closed = false
        try {
            val len = handleReturnTrafficLoop(readBuffer.capacity())
            if (len < 0) {
                closed = true
            } else if (len > 0) {
                // logger.debug("Read $len bytes")
            }
        } catch (e: Exception) {
            closed = true
        }
        if (closed) {
            logger.warn("Remote Udp channel closed")
            return false
        }
        return true
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
            outgoingQueue.put(acceptedBytes, buffer)
            acceptedBytes += buffer.limit().toUInt()
            readyToWrite()
        } catch (e: Exception) {
            logger.error("Error writing to UDP channel: $e")
            close()
        }
    }
}
