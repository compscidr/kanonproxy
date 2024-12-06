package com.jasonernst.kanonproxy

import com.jasonernst.knet.SentinelPacket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean

class ProxySession(
    private val clientAddress: InetSocketAddress,
    private val kAnonProxy: KAnonProxy,
    private val socket: DatagramSocket,
    private val sessionManager: ProxySessionManager,
) {
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
                break
            }
            logger.debug("Received response from proxy for client: $clientAddress, sending datagram back")
            val buffer = response.toByteArray()
            val datagramPacket = DatagramPacket(buffer, buffer.size, clientAddress)
            try {
                socket.send(datagramPacket)
            } catch (e: Exception) {
                logger.debug("Error trying to write to proxy server, probably shutting down: $e")
                break
            }
        }
        sessionManager.removeSession(clientAddress)
    }

    fun stop() {
        isRunning.set(false)
        runBlocking {
            if (readFromProxyJob.complete().not()) {
                readFromProxyJob.cancelAndJoin()
            }
        }
    }
}
