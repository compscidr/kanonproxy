package com.jasonernst.kanonproxy.tcp

import com.jasonernst.kanonproxy.ChangeRequest
import com.jasonernst.kanonproxy.SessionManager
import com.jasonernst.kanonproxy.TrafficAccounting
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
import java.nio.channels.SelectionKey.OP_CONNECT
import java.nio.channels.SocketChannel
import java.nio.channels.spi.AbstractSelectableChannel
import java.util.concurrent.LinkedBlockingDeque

class AnonymousTcpSession(
    initialIpHeader: IpHeader,
    initialTransportHeader: TransportHeader,
    initialPayload: ByteArray,
    returnQueue: LinkedBlockingDeque<Packet>,
    protector: VpnProtector,
    sessionManager: SessionManager,
    clientAddress: InetSocketAddress,
    trafficAccounting: TrafficAccounting,
) : TcpSession(
        initialIpHeader = initialIpHeader,
        initialTransportHeader = initialTransportHeader,
        initialPayload = initialPayload,
        returnQueue = returnQueue,
        protector = protector,
        sessionManager = sessionManager,
        clientAddress = clientAddress,
        trafficAccounting = trafficAccounting,
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
    var connectTime: Long = System.currentTimeMillis()

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
        // logger.debug("RETURN PACKETS size: {}", responsePackets.size)
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
        channel.socket().keepAlive = false
        channel.configureBlocking(false)
        protector.protectTCPSocket(channel.socket())
        startSelector()
        Thread.yield()
        tcpStateMachine.passiveOpen()
        outgoingScope.launch {
            if (isRunning.get().not()) {
                logger.debug("Session shutting down before starting")
                return@launch
            }
            val oldThreadName = Thread.currentThread().name
            Thread.currentThread().name = "Outgoing handler: ${getKey()}"
            connect()
            logger.debug("outgoing job complete")
            Thread.currentThread().name = oldThreadName
            outgoingJob.complete()
        }
    }

    private fun connect() {
        try {
            logger.debug("TCP connecting to {}:{}", initialIpHeader!!.destinationAddress, initialTransportHeader!!.destinationPort)
            // logger.debug("Adding REGISTER request to CONNECT")
            val result =
                channel.connect(
                    InetSocketAddress(initialIpHeader!!.destinationAddress, initialTransportHeader!!.destinationPort.toInt()),
                )
            if (result) {
                // this can either be connected immediately, or we'll have to wait for the selector
                logger.debug("TCP connected to ${initialIpHeader!!.destinationAddress}")
                isConnecting.set(false)
                startIncomingHandling()

                // we may have got data while waiting to connect
                if (outgoingQueue.isNotEmpty()) {
                    logger.debug("Adding CHANGE request to write")
                    synchronized(changeRequests) {
                        changeRequests.add(
                            ChangeRequest(channel as AbstractSelectableChannel, ChangeRequest.REGISTER, SelectionKey.OP_WRITE),
                        )
                    }
                } else {
                    logger.debug("Adding CHANGE request to read")
                    synchronized(changeRequests) {
                        changeRequests.add(ChangeRequest(channel, ChangeRequest.REGISTER, SelectionKey.OP_READ))
                    }
                }
            } else {
                logger.debug("CONNECT called, waiting for selector")
                // channel.finishConnect() // this makes haywire select messages show up.
            }
            selector.wakeup()
        } catch (e: Exception) {
            logger.error("Error on trying to connect: $e")
            handleExceptionOnRemoteChannel(e)
        }
    }

    fun reconnectRemoteChannel(): Boolean {
        logger.debug("Trying to reconnect to remote channel")
        try {
            channel.close()
            channel = SocketChannel.open()
            channel.socket().keepAlive = false
            channel.configureBlocking(false)
            changeRequests.add(ChangeRequest(channel, ChangeRequest.REGISTER, OP_CONNECT))
            selector.wakeup()
            Thread.yield()
            connect()
        } catch (e: Exception) {
            return false
        }
        return true
    }

    override fun read(): Boolean {
        try {
            val maxRead = tcpStateMachine.availableOutgoingBufferSpace()
            val len =
                if (maxRead > 0) {
                    handleReturnTrafficLoop(maxRead)
                } else {
                    logger.warn("No more space in outgoing buffer, waiting for more space")
                    logger.debug("Adding request to clear interest ops")
                    changeRequests.add(ChangeRequest(channel, ChangeRequest.CHANGE_OPS, 0))
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
