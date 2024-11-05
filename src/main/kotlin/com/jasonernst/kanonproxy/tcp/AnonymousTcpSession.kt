package com.jasonernst.kanonproxy.tcp

import com.jasonernst.icmp.common.v4.IcmpV4DestinationUnreachableCodes
import com.jasonernst.icmp.common.v6.IcmpV6DestinationUnreachableCodes
import com.jasonernst.kanonproxy.SessionManager
import com.jasonernst.kanonproxy.VpnProtector
import com.jasonernst.kanonproxy.icmp.IcmpFactory
import com.jasonernst.knet.Packet
import com.jasonernst.knet.SentinelPacket
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.transport.TransportHeader
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.knet.transport.tcp.options.TcpOptionMaximumSegmentSize
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.nio.channels.SocketChannel
import java.util.concurrent.LinkedBlockingDeque

class AnonymousTcpSession(
    initialIpHeader: IpHeader,
    initialTransportHeader: TransportHeader,
    initialPayload: ByteArray,
    returnQueue: LinkedBlockingDeque<Packet>,
    protector: VpnProtector,
    sessionManager: SessionManager,
) : TcpSession(
        initialIpHeader = initialIpHeader,
        initialTransportHeader = initialTransportHeader,
        initialPayload = initialPayload,
        returnQueue = returnQueue,
        protector = protector,
        sessionManager = sessionManager,
    ) {
    private val logger = LoggerFactory.getLogger(javaClass)
    override val tcpStateMachine: TcpStateMachine = TcpStateMachine(MutableStateFlow(TcpState.LISTEN), mtu(), this)

    // note: android doesn't suppor the open function with the protocol family, so just open like this and assume
    // that connect will take care of it. If it doesn't we can fall back to open with the InetSocketAddress, however,
    // that will do connect during open.
    override val channel: SocketChannel = SocketChannel.open()

    override fun handleReturnTrafficLoop(): Int {
        val len = super.handleReturnTrafficLoop()
        if (len == 0 && tcpStateMachine.tcpState.value == TcpState.CLOSE_WAIT) {
            logger.warn("We're in CLOSE_WAIT, and we have no more data to recv from remote side, sending FIN")
            val finPacket = teardown(true)
            if (finPacket != null) {
                returnQueue.add(finPacket)
            }
        }
        return len
    }

    override fun handlePacketFromClient(packet: Packet) {
        val responsePackets = tcpStateMachine.processHeaders(packet.ipHeader!!, packet.nextHeaders!! as TcpHeader, packet.payload!!)
        for (response in responsePackets) {
            logger.debug("RETURN PACKET: {}", response.nextHeaders)
            returnQueue.put(response)
        }

        if (tcpStateMachine.tcpState.value == TcpState.CLOSED) {
            logger.debug("Tcp session is closed, removing from session table, {}", this)
            // todo: we need this to be per-session at some point
            returnQueue.put(SentinelPacket)
            sessionManager.removeSession(this)
        }
    }

    init {
        protector.protectTCPSocket(channel.socket())
        tcpStateMachine.passiveOpen()
        outgoingScope.launch {
            Thread.currentThread().name = "Outgoing handler: ${getKey()}"
            try {
                logger.debug("TCP connecting to {}:{}", initialIpHeader.destinationAddress, initialTransportHeader.destinationPort)
                channel.socket().connect(
                    InetSocketAddress(initialIpHeader.destinationAddress, initialTransportHeader.destinationPort.toInt()),
                    1000,
                )
                logger.debug("TCP connected")
                startIncomingHandling()
            } catch (e: Exception) {
                // this should catch any exceptions trying to make the TCP connection (timeout, not reachable etc.)
                logger.error("Error creating the TCP session: ${e.message}")
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
                incomingQueue.clear() // prevent us from handling any incoming packets because we can't send them anywhere
                // close()
                val finPacket = teardown(true)
                if (finPacket != null) {
                    returnQueue.add(finPacket)
                }
            }

            try {
                while (channel.isOpen) {
                    do {
                        val len = handleReturnTrafficLoop()
                    } while (channel.isOpen && len > -1)
                }
            } catch (e: Exception) {
                logger.warn("Remote Tcp channel closed")
                // close()
                incomingQueue.clear() // prevent us from handling any incoming packets because we can't send them anywhere
                val finPacket = teardown(true)
                if (finPacket != null) {
                    returnQueue.add(finPacket)
                }
            }
        }
    }

    override fun close() {
        val finPacket = teardown(true)
        if (finPacket != null) {
            returnQueue.add(finPacket)
        }
        super.close() // stop the incoming and outgoing jobs
    }
}
