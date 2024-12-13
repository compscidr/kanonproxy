package com.jasonernst.kanonproxy

import com.jasonernst.icmp.common.Icmp
import com.jasonernst.icmp.linux.IcmpLinux
import com.jasonernst.knet.Packet
import com.jasonernst.packetdumper.AbstractPacketDumper
import com.jasonernst.packetdumper.DummyPacketDumper
import com.jasonernst.packetdumper.ethernet.EtherType
import com.jasonernst.packetdumper.serverdumper.PcapNgTcpServerPacketDumper
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import sun.misc.Signal
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

class Server(
    icmp: Icmp,
    private val port: Int = KAnonProxy.DEFAULT_PORT,
    private val packetDumper: AbstractPacketDumper = DummyPacketDumper,
    protector: VpnProtector = DummyProtector,
) : ProxySessionManager {
    private val logger = LoggerFactory.getLogger(javaClass)
    private lateinit var socket: DatagramSocket
    private val isRunning = AtomicBoolean(false)
    private val kAnonProxy = KAnonProxy(icmp, protector)
    private val sessions = ConcurrentHashMap<InetSocketAddress, ProxySession>()

    private lateinit var readFromClientJob: CompletableJob
    private lateinit var readFromClientJobScope: CoroutineScope

    companion object {
        private const val MAX_STREAM_BUFFER_SIZE = 1048576 // max we can write into the stream without parsing
        private const val MAX_RECEIVE_BUFFER_SIZE = 1500 // max amount we can recv in one read (should be the MTU or bigger probably)

        @JvmStatic
        fun main(args: Array<String>) {
            // listen on one port higher so we don't conflict with the client
            val packetDumper = PcapNgTcpServerPacketDumper(listenPort = PcapNgTcpServerPacketDumper.DEFAULT_PORT + 1)
            val server =
                if (args.isEmpty()) {
                    println("Using default port: ${KAnonProxy.DEFAULT_PORT}")
                    Server(IcmpLinux)
                } else {
                    if (args.size != 1) {
                        println("Usage: Server <port>")
                        return
                    }
                    val port = args[0].toInt()
                    Server(IcmpLinux, port)
                }
            packetDumper.start()
            server.start()

            Signal.handle(Signal("INT")) {
                packetDumper.stop()
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
        readFromClientJob = SupervisorJob()
        readFromClientJobScope = CoroutineScope(Dispatchers.IO + readFromClientJob)
        readFromClientJobScope.launch {
            readFromClientWriteToProxy()
        }
    }

    private fun waitUntilShutdown() {
        runBlocking {
            readFromClientJob.join()
        }
    }

    private fun readFromClientWriteToProxy() {
        Thread.currentThread().name = "Server proxy listener"
        logger.debug("Starting server on port: $port")
        socket = DatagramSocket(port)

        val buffer = ByteArray(MAX_RECEIVE_BUFFER_SIZE)
        val packet = DatagramPacket(buffer, buffer.size)
        val stream = ByteBuffer.allocate(MAX_STREAM_BUFFER_SIZE)

        while (isRunning.get()) {
            try {
                socket.receive(packet)
            } catch (e: Exception) {
                logger.warn("Error trying to receive on server socket, probably shutting down: $e")
                break
            }
            stream.put(buffer, 0, packet.length)
            stream.flip()
            val packets = Packet.parseStream(stream)
            for (p in packets) {
                packetDumper.dumpBuffer(ByteBuffer.wrap(p.toByteArray()), etherType = EtherType.DETECT)
            }
            val clientAddress = InetSocketAddress(packet.address, packet.port)
            kAnonProxy.handlePackets(packets, clientAddress)
            var newSession = false
            sessions.getOrPut(clientAddress) {
                newSession = true
                val session = ProxySession(clientAddress, kAnonProxy, socket, this, packetDumper)
                session.start()
                session
            }
            if (newSession) {
                logger.warn("New proxy session for client: $clientAddress")
            } else {
                // logger.debug("Continuing to use existing proxy session for client: $clientAddress")
            }
        }
        logger.warn("Server no longer listening")
        readFromClientJob.complete()
    }

    override fun removeSession(clientAddress: InetSocketAddress) {
        kAnonProxy.removeSessionByClientAddress(clientAddress)
        sessions.remove(clientAddress)
    }

    fun stop() {
        logger.debug("Stopping server")
        isRunning.set(false)
        socket.close()
        kAnonProxy.stop()
        logger.debug("Stopping outstanding sessions")
        sessions.values.forEach { it.stop() }
        logger.debug("All sessions stopped, stopping client reader job")
        runBlocking {
            readFromClientJob.join()
        }
        logger.debug("Server stopped")
    }
}
