package com.jasonernst.kanonproxy

import com.jasonernst.kanonproxy.KAnonProxy.Companion.MAX_STREAM_BUFFER_SIZE
import com.jasonernst.knet.SentinelPacket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

class ProxySession(
    private val clientAddress: InetSocketAddress,
    private val kAnonProxy: KAnonProxy,
    private val server: Server,
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val readFromProxyJob = SupervisorJob()
    private val readFromProxyJobScope = CoroutineScope(Dispatchers.IO + readFromProxyJob)
    private val isRunning = AtomicBoolean(false)
    val incomingProxyStream: ByteBuffer = ByteBuffer.allocate(MAX_STREAM_BUFFER_SIZE)

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
            server.enqueuePackets(listOf(OutgoingClientPacket(clientAddress, response)))
        }
    }

    fun stop() {
        isRunning.set(false)
        runBlocking {
            readFromProxyJob.cancelAndJoin()
        }
    }
}
