package com.jasonernst.kanonproxy.tcp

import com.jasonernst.knet.Packet
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

class AnonymousTcpSession(
    sourceAddress: InetAddress,
    sourcePort: UShort,
    destinationAddress: InetAddress,
    destinationPort: UShort,
    returnQueue: LinkedBlockingDeque<Packet>,
) : TcpSession(
        sourceAddress = sourceAddress,
        sourcePort = sourcePort,
        destinationAddress = destinationAddress,
        destinationPort = destinationPort,
        returnQueue = returnQueue,
    ) {
    private val logger = LoggerFactory.getLogger(javaClass)
    override val tcpStateMachine: TcpStateMachine = TcpStateMachine(TcpState.LISTEN, mtu, this)
    override val channel: SocketChannel =
        if (destinationAddress is Inet4Address) {
            SocketChannel.open(StandardProtocolFamily.INET)
        } else {
            SocketChannel.open(StandardProtocolFamily.INET6)
        }

    init {
        tcpStateMachine.passiveOpen()
        logger.debug("TCP connecting to {}:{}", destinationAddress, destinationPort)
        channel.connect(InetSocketAddress(destinationAddress, destinationPort.toInt()))
        logger.debug("TCP Connected")
        CoroutineScope(Dispatchers.IO).launch {
            handleReturnTraffic()
        }
    }
}
