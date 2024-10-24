package com.jasonernst.kanonproxy.tcp

import com.jasonernst.kanonproxy.Session
import com.jasonernst.kanonproxy.VpnProtector
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.transport.tcp.options.TcpOptionMaximumSegmentSize
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingDeque

abstract class TcpSession(
    sourceAddress: InetAddress,
    sourcePort: UShort,
    destinationAddress: InetAddress,
    destinationPort: UShort,
    returnQueue: LinkedBlockingDeque<Packet>,
    protector: VpnProtector,
) : Session(
        sourceAddress = sourceAddress,
        sourcePort = sourcePort,
        destinationAddress = destinationAddress,
        destinationPort = destinationPort,
        protocol = IpType.TCP.value,
        returnQueue = returnQueue,
        protector = protector,
    ) {
    private val logger = LoggerFactory.getLogger(javaClass)

    protected val mtu =
        if (destinationAddress is Inet4Address) {
            TcpOptionMaximumSegmentSize.defaultIpv4MSS
        } else {
            TcpOptionMaximumSegmentSize.defaultIpv6MSS
        }

    abstract val tcpStateMachine: TcpStateMachine
    var lastestACKs = CopyOnWriteArrayList<RetransmittablePacket>()

    override fun handlePayloadFromInternet(payload: ByteArray) {
        val buffer = ByteBuffer.wrap(payload)
        while (buffer.hasRemaining()) {
            tcpStateMachine.enqueueOutgoingData(buffer)
            val packets = tcpStateMachine.encapsulateOutgoingData()
            returnQueue.addAll(packets)
        }
    }

    /**
     * Should be called to cleanly shut down the session. If in state LISTEN, or SYN_SENT, delete the TCB and return
     * to closed state.
     *
     * If in state SYN_RECV, ESTAB, CLOSE_WAIT, send FIN.
     *
     * else do nothing.
     */
    fun close(swapSourceAndDestination: Boolean = true): Packet? {
        logger.debug("Tcp session CLOSE function called in tcpState: ${tcpStateMachine.tcpState.value}")
        val finPacket =
            TcpHeaderFactory.createFinPacket(
                sourceAddress,
                destinationAddress,
                sourcePort,
                destinationPort,
                tcpStateMachine.transmissionControlBlock!!.snd_nxt,
                tcpStateMachine.transmissionControlBlock!!.rcv_nxt,
                swapSourceAndDestination,
                transmissionControlBlock = tcpStateMachine.transmissionControlBlock,
            )
        tcpStateMachine.transmissionControlBlock!!.snd_nxt += 1u
        tcpStateMachine.transmissionControlBlock!!.fin_seq = tcpStateMachine.transmissionControlBlock!!.snd_nxt
        when (tcpStateMachine.tcpState.value) {
            TcpState.LISTEN, TcpState.SYN_SENT -> {
                logger.debug("Transitioning to CLOSED")
                tcpStateMachine.tcpState.value = TcpState.CLOSED
                tcpStateMachine.transmissionControlBlock = null
            }
            TcpState.SYN_RECEIVED, TcpState.ESTABLISHED -> {
                logger.debug("Transitioning to FIN_WAIT_1")
                tcpStateMachine.tcpState.value = TcpState.FIN_WAIT_1
                return finPacket
            }
            TcpState.CLOSE_WAIT -> {
                logger.debug("Transitioning to LAST_ACK")
                tcpStateMachine.tcpState.value = TcpState.LAST_ACK
                return finPacket
            }
            else -> {
                logger.warn("Close called in state that doesn't make sense: ${tcpStateMachine.tcpState}")
            }
        }
        return null
    }

    fun reestablishConnection() {
        TODO()
    }
}
