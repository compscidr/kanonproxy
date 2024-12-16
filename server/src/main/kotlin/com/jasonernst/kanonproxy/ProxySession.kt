package com.jasonernst.kanonproxy

import com.jasonernst.knet.SentinelPacket
import com.jasonernst.packetdumper.AbstractPacketDumper
import com.jasonernst.packetdumper.DummyPacketDumper
import com.jasonernst.packetdumper.ethernet.EtherType
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
    private val sessionManager: ProxySessionManager,
    private val packetDumper: AbstractPacketDumper = DummyPacketDumper,
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
        Thread.currentThread().name = "ReadProxy: $clientAddress"
        while (isRunning.get()) {
            // logger.debug("Waiting for response from proxy for client: $clientAddress")
            val response = kAnonProxy.takeResponse(clientAddress)
            if (response is SentinelPacket) {
                logger.warn("Received sentinel packet, stopping ProxySession: $clientAddress")
                break
            }
            // logger.debug("Received response from proxy for client: $clientAddress, sending datagram back")
            val buffer = ByteBuffer.wrap(response.toByteArray())
            packetDumper.dumpBuffer(buffer, etherType = EtherType.DETECT)
            sessionManager.enqueueOutgoing(clientAddress, buffer)
        }
        sessionManager.removeSession(clientAddress)
        isRunning.set(false)
        logger.info("Proxy session $clientAddress has been stopped")
        readFromProxyJob.complete()
    }

    fun stop() {
        logger.debug("Stopping proxy session")
        isRunning.set(false)
        runBlocking {
            readFromProxyJob.cancelAndJoin()
        }
        logger.debug("Proxy session stopped")
    }
}
