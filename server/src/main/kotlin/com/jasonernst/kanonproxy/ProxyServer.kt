package com.jasonernst.kanonproxy

import com.jasonernst.icmp.common.Icmp
import com.jasonernst.icmp.linux.IcmpLinux
import com.jasonernst.kanonproxy.ChangeRequest.Companion.CHANGE_OPS
import com.jasonernst.kanonproxy.ChangeRequest.Companion.REGISTER
import com.jasonernst.knet.Packet
import com.jasonernst.packetdumper.AbstractPacketDumper
import com.jasonernst.packetdumper.DummyPacketDumper
import com.jasonernst.packetdumper.ethernet.EtherType
import com.jasonernst.packetdumper.filedumper.AbstractFilePacketDumper
import com.jasonernst.packetdumper.serverdumper.AbstractServerPacketDumper
import com.jasonernst.packetdumper.serverdumper.PcapNgTcpServerPacketDumper
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import sun.misc.Signal
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey.OP_READ
import java.nio.channels.SelectionKey.OP_WRITE
import java.nio.channels.Selector
import java.util.LinkedList
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingDeque
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The datagram channel should be configured as non-blocking and already bound to the port it is
 * listening on before being passed to here.
 */
class ProxyServer(
    icmp: Icmp,
    private val datagramChannel: DatagramChannel,
    private val packetDumper: AbstractPacketDumper = DummyPacketDumper,
    protector: VpnProtector = DummyProtector,
    trafficAccounting: TrafficAccounting = DummyTrafficAccount,
) : ProxySessionManager {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val isRunning = AtomicBoolean(false)
    private val kAnonProxy = KAnonProxy(icmp, protector, trafficAccounting)
    private val sessions = ConcurrentHashMap<InetSocketAddress, ProxySession>()

    private lateinit var selector: Selector
    private lateinit var selectorJob: CompletableJob
    private lateinit var selectorScope: CoroutineScope
    private val outgoingQueue = LinkedBlockingDeque<Pair<InetSocketAddress, ByteBuffer>>() // queue of data to be sent to clients
    private val changeRequests = LinkedList<ChangeRequest>()

    companion object {
        private val staticLogger = LoggerFactory.getLogger(ProxyServer::class.java)
        private const val MAX_RECEIVE_BUFFER_SIZE = 1500 // max amount we can recv in one read (should be the MTU or bigger probably)

        @JvmStatic
        fun main(args: Array<String>) {
            // listen on one port higher so we don't conflict with the client
            val packetDumper = PcapNgTcpServerPacketDumper(listenPort = PcapNgTcpServerPacketDumper.DEFAULT_PORT + 1)

            val datagramChannel = DatagramChannel.open()
            if (args.isEmpty()) {
                staticLogger.debug("Server listening on default port: ${KAnonProxy.DEFAULT_PORT}")
                datagramChannel.bind(InetSocketAddress(KAnonProxy.DEFAULT_PORT))
            } else {
                if (args.size != 1) {
                    staticLogger.warn("Usage: Server <port>")
                    return
                }
                val port = args[0].toInt()
                datagramChannel.bind(InetSocketAddress(port))
            }
            datagramChannel.configureBlocking(false)

            val server = ProxyServer(icmp = IcmpLinux, datagramChannel = datagramChannel)
            packetDumper.start()
            server.start()

            Signal.handle(Signal("INT")) {
                server.stop()
            }

            server.waitUntilShutdown()
        }
    }

    fun start() {
        if (isRunning.get()) {
            logger.warn("Server is already running")
            return
        }
        isRunning.set(true)
        kAnonProxy.start()
        selector = Selector.open()

        selectorJob = SupervisorJob()
        selectorScope = CoroutineScope(Dispatchers.IO + selectorJob)
        selectorScope.launch {
            selectorLoop()
        }
    }

    private fun waitUntilShutdown() {
        runBlocking {
            selectorJob.join()
        }
    }

    private fun selectorLoop() {
        datagramChannel.register(selector, OP_READ)

        while (isRunning.get()) {
            synchronized(changeRequests) {
                for (changeRequest in changeRequests) {
                    when (changeRequest.type) {
                        REGISTER -> {
                            // logger.debug("Processing REGISTER: ${changeRequest.ops}")
                            changeRequest.channel.register(selector, changeRequest.ops)
                        }

                        CHANGE_OPS -> {
                            // logger.debug("Processing CHANGE_OPS: ${changeRequest.ops}")
                            val key = changeRequest.channel.keyFor(selector)
                            key.interestOps(changeRequest.ops)
                        }
                    }
                }
                changeRequests.clear()
            }

            try {
                val numKeys = selector.select()
                // we won't get any keys if we wakeup the selector before we select
                // (ie, when we make changes to the keys or interest-ops)
                if (numKeys > 0) {
                    val selectedKeys = selector.selectedKeys()
                    val keyStream = selectedKeys.parallelStream()
                    keyStream.forEach {
                        if (it.isReadable && it.isValid) {
                            readFromClient()
                        }
                        if (it.isWritable && it.isValid) {
                            if (outgoingQueue.isNotEmpty()) {
                                val outgoingPair = outgoingQueue.take()
                                val clientAddress = outgoingPair.first
                                val buffer = outgoingPair.second
                                while (buffer.hasRemaining()) {
                                    datagramChannel.send(buffer, clientAddress)
                                }
                            } else {
                                it.interestOps(OP_READ)
                            }
                        }
                    }
                    selectedKeys.clear()
                }
            } catch (e: Exception) {
                logger.warn("Exception on select, probably shutting down: $e")
                break
            }
        }
        selectorJob.complete()
    }

    private fun readFromClient() {
        // since each of these receives could be potentially from separate clients, we can't try
        // to parse different subsequent reads together - it MUST all fit in a single read.
        val buffer = ByteBuffer.allocate(MAX_RECEIVE_BUFFER_SIZE)
        val clientAddress = datagramChannel.receive(buffer) as InetSocketAddress
        buffer.flip()
        val packets = Packet.parseStream(buffer)
        for (p in packets) {
            packetDumper.dumpBuffer(ByteBuffer.wrap(p.toByteArray()), etherType = EtherType.DETECT)
        }
        kAnonProxy.handlePackets(packets, clientAddress)
        var newSession = false
        sessions.getOrPut(clientAddress) {
            newSession = true
            val session = ProxySession(clientAddress, kAnonProxy, this, packetDumper)
            session.start()
            session
        }
        if (newSession) {
            logger.warn("New proxy session for client: $clientAddress")
        } else {
            // logger.debug("Continuing to use existing proxy session for client: $clientAddress")
        }
    }

    override fun enqueueOutgoing(
        clientAddress: InetSocketAddress,
        buffer: ByteBuffer,
    ) {
        outgoingQueue.add(Pair(clientAddress, buffer))
        synchronized(changeRequests) {
            changeRequests.add(ChangeRequest(datagramChannel, CHANGE_OPS, OP_WRITE))
        }
        selector.wakeup()
    }

    override fun removeSession(clientAddress: InetSocketAddress) {
        kAnonProxy.removeSessionByClientAddress(clientAddress)
        sessions.remove(clientAddress)
    }

    fun stop() {
        logger.debug("Stopping server")
        isRunning.set(false)
        datagramChannel.close()
        kAnonProxy.stop()
        selector.close()
        if (packetDumper is AbstractServerPacketDumper) {
            packetDumper.stop()
        } else if (packetDumper is AbstractFilePacketDumper) {
            packetDumper.close()
        }
        logger.debug("Stopping outstanding sessions")
        sessions.values.forEach { it.stop() }
        logger.debug("All sessions stopped, stopping selector job")
        runBlocking {
            selectorJob.join()
        }
        logger.debug("Server stopped")
    }
}
