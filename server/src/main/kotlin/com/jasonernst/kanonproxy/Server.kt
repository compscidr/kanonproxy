package com.jasonernst.kanonproxy

import com.jasonernst.icmp.linux.IcmpLinux
import com.jasonernst.knet.Packet
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

class Server(private val port: Int = 8080) {

    private lateinit var socket: DatagramSocket
    private val isRunning = AtomicBoolean(false)
    private val kAnonProxy = KAnonProxy(IcmpLinux)
    private val sessions = ConcurrentHashMap<InetSocketAddress, ProxySession>()

    private val readFromClientJob = SupervisorJob()
    private val readFromClientJobScope = CoroutineScope(Dispatchers.IO + readFromClientJob)

    companion object {
        private const val MAX_STREAM_BUFFER_SIZE = 1048576 // max we can write into the stream without parsing
        private const val MAX_RECEIVE_BUFFER_SIZE = 1500   // max amount we can recv in one read (should be the MTU or bigger probably)

        @JvmStatic
        fun main(args: Array<String>) {
            val server = if (args.isEmpty()) {
                println("Using default port: 8080")
                Server()
            } else {
                if (args.size != 1) {
                    println("Usage: Server <port>")
                    return
                }
                val port = args[0].toInt()
                Server(port)
            }
            server.start()
        }
    }

    fun start() {
        if (isRunning.get()) {
            println("Server is already running")
            return
        }
        println("Starting server on port: $port")
        socket = DatagramSocket(port)
        isRunning.set(true)
        kAnonProxy.start()
        readFromClientJobScope.launch {
            readFromClientWriteToProxy()
        }

        runBlocking {
            readFromClientJob.join()
        }
    }

    private fun readFromClientWriteToProxy() {
        val buffer = ByteArray(MAX_RECEIVE_BUFFER_SIZE)
        val packet = DatagramPacket(buffer, buffer.size)
        val stream = ByteBuffer.allocate(MAX_STREAM_BUFFER_SIZE)

        while (isRunning.get()) {
            socket.receive(packet)
            stream.put(buffer, 0, packet.length)
            stream.flip()
            val packets = Packet.parseStream(stream)
            val clientAddress = InetSocketAddress(packet.address, packet.port)
            kAnonProxy.handlePackets(packets, clientAddress)
            sessions.getOrPut(clientAddress) {
                val session = ProxySession(clientAddress, kAnonProxy, socket)
                session.start()
                session
            }
        }
    }

    fun stop() {
        isRunning.set(false)
        socket.close()
        kAnonProxy.stop()
        sessions.values.forEach { it.stop() }
    }
}