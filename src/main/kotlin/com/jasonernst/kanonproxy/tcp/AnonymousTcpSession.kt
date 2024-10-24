package com.jasonernst.kanonproxy.tcp

import com.jasonernst.kanonproxy.VpnProtector
import com.jasonernst.knet.Packet
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.channels.SocketChannel
import java.util.concurrent.LinkedBlockingDeque

class AnonymousTcpSession(
    sourceAddress: InetAddress,
    sourcePort: UShort,
    destinationAddress: InetAddress,
    destinationPort: UShort,
    returnQueue: LinkedBlockingDeque<Packet>,
    protector: VpnProtector,
) : TcpSession(
        sourceAddress = sourceAddress,
        sourcePort = sourcePort,
        destinationAddress = destinationAddress,
        destinationPort = destinationPort,
        returnQueue = returnQueue,
        protector = protector,
    ) {
    private val logger = LoggerFactory.getLogger(javaClass)
    override val tcpStateMachine: TcpStateMachine = TcpStateMachine(MutableStateFlow(TcpState.LISTEN), mtu, this)

    // note: android doesn't suppor the open function with the protocol family, so just open like this and assume
    // that connect will take care of it. If it doesn't we can fall back to open with the InetSocketAddress, however,
    // that will do connect during open.
    override val channel: SocketChannel = SocketChannel.open()

    override fun handleReturnTrafficLoop(): Int {
        val len = super.handleReturnTrafficLoop()
        if (len == 0 && tcpStateMachine.tcpState.value == TcpState.CLOSE_WAIT) {
            close()
        }
        return len
    }

    init {
        protector.protectTCPSocket(channel.socket())
        tcpStateMachine.passiveOpen()
        logger.debug("TCP connecting to {}:{}", destinationAddress, destinationPort)
        channel.connect(InetSocketAddress(destinationAddress, destinationPort.toInt()))
        logger.debug("TCP Connected")
        CoroutineScope(Dispatchers.IO).launch {
            try {
                while (channel.isOpen) {
                    do {
                        val len = handleReturnTrafficLoop()
                    } while (channel.isOpen && len > -1)
                }
            } catch (e: Exception) {
                logger.warn("Remote Tcp channel closed")
                close()
            }
        }
    }

    private fun close(): Packet? {
        if (channel.isOpen) {
            channel.close()
        }
        return super.close(true)
    }
}
