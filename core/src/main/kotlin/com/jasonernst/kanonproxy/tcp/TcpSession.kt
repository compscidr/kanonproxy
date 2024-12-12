package com.jasonernst.kanonproxy.tcp

import com.jasonernst.kanonproxy.Session
import com.jasonernst.kanonproxy.SessionManager
import com.jasonernst.kanonproxy.VpnProtector
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.transport.TransportHeader
import com.jasonernst.knet.transport.tcp.options.TcpOptionMaximumSegmentSize
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.util.concurrent.LinkedBlockingDeque
import java.util.concurrent.atomic.AtomicBoolean

abstract class TcpSession(
    initialIpHeader: IpHeader?,
    initialTransportHeader: TransportHeader?,
    initialPayload: ByteArray?,
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
    val isPsh = AtomicBoolean(false) // set when we have accepted a PSH packet

    // set when teardown has been called but the outgoing buffer is not empty
    val tearDownPending = AtomicBoolean(false)

    protected open val mtu =
        if (initialIpHeader == null) {
            logger.warn("Initial IP header is null, can't determine MTU")
            0u
        } else if (initialIpHeader.destinationAddress is Inet4Address) {
            TcpOptionMaximumSegmentSize.defaultIpv4MSS
        } else {
            TcpOptionMaximumSegmentSize.defaultIpv6MSS
        }

    abstract val tcpStateMachine: TcpStateMachine

    override fun handlePayloadFromInternet(payload: ByteArray) {
        val buffer = ByteBuffer.wrap(payload)
        while (buffer.hasRemaining()) {
            tcpStateMachine.enqueueOutgoingData(buffer)
        }
        val packets = tcpStateMachine.encapsulateOutgoingData(requiresLock = true)
        logger.debug("Encapsulated ${packets.size} packets")
        for (packet in packets) {
            logger.debug("  packet: $packet")
        }
        returnQueue.addAll(packets)
    }

    /**
     * Should be called to cleanly tear down the session. If in state LISTEN, or SYN_SENT, delete the TCB and return
     * to closed state.
     *
     * If in state SYN_RECV, ESTAB, CLOSE_WAIT, send FIN.
     *
     * else do nothing.
     */
    fun teardown(
        swapSourceAndDestination: Boolean = true,
        requiresLock: Boolean,
    ): Packet? {
        if (tcpStateMachine.tcpState.value == TcpState.CLOSED || tcpStateMachine.tcpState.value == TcpState.TIME_WAIT || tcpStateMachine.tcpState.value == TcpState.LAST_ACK) {
            // prevent going into all this if we're already closed
            return null
        }
        val packet =
            runBlocking {
                if (requiresLock) {
                    // logger.warn("TCP TEARDOWN CALLED, WAITING FOR LOCK")
                    tcpStateMachine.tcbMutex.lock()
                    // logger.warn("TCP TEARDOWN LOCK ACQUIRED")
                }

                logger.debug(
                    "Tcp session TEARDOWN function called in tcpState: ${tcpStateMachine.tcpState.value} swap?: $swapSourceAndDestination",
                )

                if (tcpStateMachine.outgoingBytesToSend() > 0) {
                    logger.debug("Outgoing bytes to send, setting TEARDOWN pending")
                    tearDownPending.set(true)
                    return@runBlocking null
                } else {
                    // logger.debug("No outgoing bytes to send, proceeding with TEARDOWN")
                }

                if (tcpStateMachine.transmissionControlBlock == null) {
                    logger.debug("No TCB, returning to CLOSED")
                    tcpStateMachine.tcpState.value = TcpState.CLOSED
                    return@runBlocking null
                }
                if (initialIpHeader == null || initialTransportHeader == null) {
                    logger.error("Initial headers are null, can't send FIN")
                    tcpStateMachine.tcpState.value = TcpState.CLOSED
                    return@runBlocking null
                }
                val finPacket =
                    if (tcpStateMachine.transmissionControlBlock!!.fin_seq != 0u) {
                        logger.debug("FIN already sent, not sending another")
                        null
                    } else {
                        TcpHeaderFactory.createFinPacket(
                            initialIpHeader!!.sourceAddress,
                            initialIpHeader!!.destinationAddress,
                            initialTransportHeader!!.sourcePort,
                            initialTransportHeader!!.destinationPort,
                            tcpStateMachine.transmissionControlBlock!!.snd_nxt,
                            tcpStateMachine.transmissionControlBlock!!.rcv_nxt,
                            swapSourceAndDestination,
                            transmissionControlBlock = tcpStateMachine.transmissionControlBlock,
                        )
                    }

                if (finPacket != null) {
                    // only do this if we're actually sending a FIN, otherwise we'll wind up with a bad fin_seq and
                    // never close correctly.
                    tcpStateMachine.transmissionControlBlock!!.snd_nxt += 1u
                    tcpStateMachine.transmissionControlBlock!!.fin_seq =
                        tcpStateMachine.transmissionControlBlock!!.snd_nxt
                }

                when (tcpStateMachine.tcpState.value) {
                    TcpState.LISTEN, TcpState.SYN_SENT -> {
                        logger.debug("Transitioning to CLOSED")
                        tcpStateMachine.tcpState.value = TcpState.CLOSED
                        tcpStateMachine.transmissionControlBlock = null
                    }

                    TcpState.SYN_RECEIVED, TcpState.ESTABLISHED -> {
                        logger.debug("Transitioning to FIN_WAIT_1, sending FIN: $finPacket")
                        tcpStateMachine.tcpState.value = TcpState.FIN_WAIT_1
                        tcpStateMachine.stopRtoAndDelayedAck()
                        return@runBlocking finPacket
                    }

                    TcpState.CLOSE_WAIT -> {
                        logger.debug("Transitioning to LAST_ACK, sending FIN: $finPacket")
                        tcpStateMachine.tcpState.value = TcpState.LAST_ACK
                        return@runBlocking finPacket
                    }

                    else -> {
                        logger.warn("TEARDOWN called in state that doesn't make sense: ${tcpStateMachine.tcpState.value}")
                    }
                }
                return@runBlocking null
            }
        if (requiresLock) {
            tcpStateMachine.tcbMutex.unlock()
            // logger.warn("TCP TEARDOWN LOCK RELEASED")
        }
        return packet
    }

    open fun mtu(): UShort =
        when (initialIpHeader?.destinationAddress) {
            is Inet4Address -> {
                TcpOptionMaximumSegmentSize.defaultIpv4MSS
            }

            is Inet6Address -> {
                TcpOptionMaximumSegmentSize.defaultIpv6MSS
            }

            else -> {
                0u
            }
        }
}
