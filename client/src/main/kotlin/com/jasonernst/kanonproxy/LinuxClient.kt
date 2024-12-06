package com.jasonernst.kanonproxy

import com.jasonernst.kanonproxy.tuntap.TunTapDevice
import java.net.InetSocketAddress

class LinuxClient(socketAddress: InetSocketAddress = InetSocketAddress("127.0.0.1", 8080)): Client(socketAddress) {
    private val tunTapDevice = TunTapDevice()

    init {
        tunTapDevice.open()
    }

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            val client =
                if (args.isEmpty()) {
                    println("Using default server: 127.0.0.1 8080")
                    LinuxClient()
                } else {
                    if (args.size != 2) {
                        println("Usage: Client <server> <port>")
                        return
                    }
                    val server = args[0]
                    val port = args[1].toInt()
                    LinuxClient(InetSocketAddress(server, port))
                }
            client.connect()
            client.waitUntilShutdown()
        }
    }

    override fun tunRead(readBytes: ByteArray, bytesToRead: Int): Int {
        return tunTapDevice.read(readBytes, bytesToRead)
    }

    override fun tunWrite(writeBytes: ByteArray) {
        tunTapDevice.write(writeBytes)
    }
}