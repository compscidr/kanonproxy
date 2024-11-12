package com.jasonernst.kanonproxy

import com.jasonernst.knet.SentinelPacket
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory

class ProxySession(private val clientAddress: InetSocketAddress, private val kAnonProxy: KAnonProxy, private val socket: DatagramSocket) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val readFromProxyJob = SupervisorJob()
    private val readFromProxyJobScope = CoroutineScope(Dispatchers.IO + readFromProxyJob)
    private val isRunning = AtomicBoolean(false)

    fun start() {
        if (isRunning.get()) {
            logger.warn("ProxySession is already running")
            return
        }
        isRunning.set(true)
        readFromProxyJobScope.launch {
            readFromProxyWriteToClient()
        }
    }

    private fun readFromProxyWriteToClient() {
        while (isRunning.get()) {
            logger.debug("Waiting for response from proxy for client: $clientAddress")
            val response = kAnonProxy.takeResponse(clientAddress)
            if (response is SentinelPacket) {
                logger.warn("Received sentinel packet, stopping ProxySession: $clientAddress")
                isRunning.set(false)
            }
            logger.debug("Received response from proxy for client: $clientAddress, sending datagram back")
            val buffer = response.toByteArray()
            val datagramPacket = DatagramPacket(buffer, buffer.size, clientAddress)
            socket.send(datagramPacket)
        }
    }

    fun stop() {
        isRunning.set(false)
        runBlocking {
            readFromProxyJob.cancelAndJoin()
        }
    }
}