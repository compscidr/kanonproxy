package com.jasonernst.kanonproxy

import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.transport.tcp.options.TcpOptionMaximumSegmentSize
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.StandardProtocolFamily
import java.nio.channels.SocketChannel
import java.util.concurrent.LinkedBlockingDeque

open class TcpSession(
    sourceIp: InetAddress,
    sourcePort: UShort,
    destinationIp: InetAddress,
    destinationPort: UShort,
    returnQueue: LinkedBlockingDeque<Packet>,
) : Session(
        sourceIp = sourceIp,
        sourcePort = sourcePort,
        destinationIp = destinationIp,
        destinationPort = destinationPort,
        protocol = IpType.TCP.value,
        returnQueue = returnQueue,
    ) {

    private val logger = LoggerFactory.getLogger(javaClass)
    override val channel: SocketChannel =
        if (destinationIp is Inet4Address) {
            SocketChannel.open(StandardProtocolFamily.INET)
        } else {
            SocketChannel.open(StandardProtocolFamily.INET6)
        }
    protected val mtu = if (destinationIp is Inet4Address) {
        TcpOptionMaximumSegmentSize.defaultIpv4MSS
    } else {
        TcpOptionMaximumSegmentSize.defaultIpv6MSS
    }
    open val tcpStateMachine: TcpStateMachine = TcpStateMachine(TcpState.LISTEN, mtu, this)

    init {
        CoroutineScope(Dispatchers.IO).launch {
            logger.debug("TCP connecting to {}:{}", destinationIp, destinationPort)
            channel.connect(InetSocketAddress(destinationIp, destinationPort.toInt()))
            logger.debug("TCP Connected")
            handleReturnTraffic()
        }
    }

    override fun handlePayloadFromInternet(payload: ByteArray) {
        TODO()
    }

    fun reestablishConnection() {
        TODO()
    }
}
