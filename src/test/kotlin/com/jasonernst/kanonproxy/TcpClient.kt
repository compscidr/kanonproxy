package com.jasonernst.kanonproxy

import com.jasonernst.knet.Packet
import java.net.InetAddress
import java.util.concurrent.LinkedBlockingDeque

/**
 * A "TCP client" that has its own state machine, processes packets, and generates new packets to send.
 *
 * Can also send a data stream and receive one.
 */
class TcpClient(
    sourceAddress: InetAddress, destinationAddress: InetAddress, sourcePort: UShort, destinationPort: UShort, outgoingQueue: LinkedBlockingDeque<Packet>
): TcpSession(sourceIp = sourceAddress, sourcePort = sourcePort, destinationIp = destinationAddress, destinationPort = destinationPort, outgoingQueue) {
    override val tcpStateMachine = TcpStateMachine(TcpState.CLOSED, mtu, this)

    fun connect() {
        val initialSequenceNumber =
        tcpStateMachine.tcpState = TcpState.SYN_SENT
    }
}