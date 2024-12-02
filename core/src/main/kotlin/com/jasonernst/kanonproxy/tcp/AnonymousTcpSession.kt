package com.jasonernst.kanonproxy.tcp

import com.jasonernst.kanonproxy.ChangeRequest
import com.jasonernst.kanonproxy.SessionManager
import com.jasonernst.kanonproxy.VpnProtector
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.transport.TransportHeader
import com.jasonernst.knet.transport.tcp.TcpHeader
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress
import java.nio.channels.SelectionKey
import java.nio.channels.SocketChannel
import java.util.concurrent.LinkedBlockingDeque
import java.util.concurrent.atomic.AtomicBoolean

class AnonymousTcpSession(
    initialIpHeader: IpHeader,
    initialTransportHeader: TransportHeader,
    initialPayload: ByteArray,
    returnQueue: LinkedBlockingDeque<Packet>,
    protector: VpnProtector,
    sessionManager: SessionManager,
    clientAddress: InetSocketAddress,
) : TcpSession(
        initialIpHeader = initialIpHeader,
        initialTransportHeader = initialTransportHeader,
        initialPayload = initialPayload,
        returnQueue = returnQueue,
        protector = protector,
        sessionManager = sessionManager,
        clientAddress = clientAddress,
    ) {
    companion object {
        const val CONNECTION_POLL_MS: Long = 500
    }

    private val logger = LoggerFactory.getLogger(javaClass)
    override val tcpStateMachine: TcpStateMachine = TcpStateMachine(MutableStateFlow(TcpState.LISTEN), mtu(), this)

    // note: android doesn't support the open function with the protocol family, so just open like this and assume
    // that connect will take care of it. If it doesn't we can fall back to open with the InetSocketAddress, however,
    // that will do connect during open.
    override var channel: SocketChannel = SocketChannel.open()
    var connectTime: Long = 0L
    val isConnecting = AtomicBoolean(true)

    override fun handleReturnTrafficLoop(maxRead: Int): Int {
        val len = super.handleReturnTrafficLoop(maxRead)
        if (len == 0 && tcpStateMachine.tcpState.value == TcpState.CLOSE_WAIT) {
            logger.warn("We're in CLOSE_WAIT, and we have no more data to recv from remote side, sending FIN")
            val finPacket = teardown(requiresLock = true)
            if (finPacket != null) {
                tcpStateMachine.enqueueRetransmit(finPacket)
                returnQueue.add(finPacket)
            }
        }
        return len
    }

    override fun handlePacketFromClient(packet: Packet) {
        val responsePackets = tcpStateMachine.processHeaders(packet.ipHeader!!, packet.nextHeaders!! as TcpHeader, packet.payload!!)
        logger.debug("RETURN PACKETS size: {}", responsePackets.size)
        returnQueue.addAll(responsePackets)
//        for (response in responsePackets) {
//            logger.debug("RETURN PACKET: {}", response.nextHeaders)
//            returnQueue.add(response)
//            logger.debug("RETURN QUEUE size: ${returnQueue.size}")
//        }

        if (tcpStateMachine.tcpState.value == TcpState.CLOSED) {
            logger.debug("Tcp session is closed, removing from session table, {}", this)
            super.close(removeSession = true, packet = null, true)
        }
    }

    init {
        startSelector()
        protector.protectTCPSocket(channel.socket())
        tcpStateMachine.passiveOpen()
        outgoingScope.launch {
            Thread.currentThread().name = "Outgoing handler: ${getKey()}"
            try {
                logger.debug("TCP connecting to {}:{}", initialIpHeader.destinationAddress, initialTransportHeader.destinationPort)
                channel.socket().keepAlive = true
                channel.socket().soTimeout = 0
                channel.configureBlocking(false)
                connectTime = System.currentTimeMillis()
                val result =
                    channel.connect(
                        InetSocketAddress(initialIpHeader.destinationAddress, initialTransportHeader.destinationPort.toInt()),
                    )
                if (result) {
                    // this can either be connected immediately, or we'll have to wait for the selector
                    logger.debug("TCP connected to ${initialIpHeader.destinationAddress}")
                    synchronized(changeRequests) {
                        changeRequests.add(ChangeRequest(channel, ChangeRequest.REGISTER, SelectionKey.OP_READ))
                    }
                    startIncomingHandling()
                } else {
                    logger.debug("CONNECT called, waiting for selector")
                    synchronized(changeRequests) {
                        changeRequests.add(ChangeRequest(channel, ChangeRequest.REGISTER, SelectionKey.OP_CONNECT))
                    }
                }
                selector.wakeup()
            } catch (e: Exception) {
                handleExceptionOnRemoteChannel(e)
            }
        }
    }

    override fun read(): Boolean {
        try {
            val maxRead = tcpStateMachine.availableOutgoingBufferSpace()
            val len =
                if (maxRead > 0) {
                    handleReturnTrafficLoop(maxRead)
                } else {
                    logger.warn("No more space in outgoing buffer, waiting for more space")
                    0
                }
            if (len < 0) {
                logger.warn("Remote Tcp channel closed")
                val finPacket = teardown(requiresLock = true)
                if (finPacket != null) {
                    returnQueue.add(finPacket)
                    tcpStateMachine.enqueueRetransmit(finPacket)
                }
                return false
            }
        } catch (e: Exception) {
            logger.warn("Remote Tcp channel closed ${e.message}")
            val finPacket = teardown(requiresLock = true)
            if (finPacket != null) {
                returnQueue.add(finPacket)
                tcpStateMachine.enqueueRetransmit(finPacket)
            }
            return false
        }
        return true
    }
}
