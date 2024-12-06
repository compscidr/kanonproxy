package com.jasonernst.kanonproxy

import com.jasonernst.kanonproxy.tuntap.TunTapDevice
import com.jasonernst.packetdumper.AbstractPacketDumper
import com.jasonernst.packetdumper.DummyPacketDumper
import com.jasonernst.packetdumper.serverdumper.PcapNgTcpServerPacketDumper
import sun.misc.Signal
import java.net.InetSocketAddress

class LinuxClient(
    socketAddress: InetSocketAddress = InetSocketAddress("127.0.0.1", 8080),
    packetDumper: AbstractPacketDumper = DummyPacketDumper,
) : Client(socketAddress, packetDumper) {
    private val tunTapDevice = TunTapDevice()

    init {
        tunTapDevice.open()
    }

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            val packetDumper = PcapNgTcpServerPacketDumper()
            packetDumper.start()
            val client =
                if (args.isEmpty()) {
                    println("Using default server: 127.0.0.1 8080")
                    LinuxClient(packetDumper = packetDumper)
                } else {
                    if (args.size != 2) {
                        println("Usage: Client <server> <port>")
                        return
                    }
                    val server = args[0]
                    val port = args[1].toInt()
                    LinuxClient(socketAddress = InetSocketAddress(server, port), packetDumper = packetDumper)
                }
            client.connect()

            Signal.handle(Signal("INT")) {
                client.close()
                packetDumper.stop()
            }

            client.waitUntilShutdown()
        }
    }

    override fun tunRead(
        readBytes: ByteArray,
        bytesToRead: Int,
    ): Int = tunTapDevice.read(readBytes, bytesToRead)

    override fun tunWrite(writeBytes: ByteArray) {
        tunTapDevice.write(writeBytes)
    }
}
