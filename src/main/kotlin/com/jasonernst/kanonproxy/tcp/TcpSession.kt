package com.jasonernst.kanonproxy.tcp

import com.jasonernst.kanonproxy.Session
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
) : Session(
        sourceAddress = sourceAddress,
        sourcePort = sourcePort,
        destinationAddress = destinationAddress,
        destinationPort = destinationPort,
        protocol = IpType.TCP.value,
        returnQueue = returnQueue,
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
        val packets = tcpStateMachine.encapsulateBuffer(ByteBuffer.wrap(payload))
        returnQueue.addAll(packets)
    }

    fun reestablishConnection() {
        TODO()
    }
}
