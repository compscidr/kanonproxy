package com.jasonernst.kanonproxy

import com.jasonernst.kanonproxy.KAnonProxy.Companion.DEFAULT_PORT
import com.jasonernst.kanonproxy.tuntap.TunTapDevice
import com.jasonernst.packetdumper.AbstractPacketDumper
import com.jasonernst.packetdumper.DummyPacketDumper
import com.jasonernst.packetdumper.serverdumper.PcapNgTcpServerPacketDumper
import org.slf4j.LoggerFactory
import sun.misc.Signal
import java.net.InetSocketAddress
import java.nio.channels.DatagramChannel

class LinuxProxyClient(
    datagramChannel: DatagramChannel,
    packetDumper: AbstractPacketDumper = DummyPacketDumper,
) : ProxyClient(datagramChannel, packetDumper) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val tunTapDevice = TunTapDevice()

    init {
        tunTapDevice.open()
    }

    companion object {
        private val staticLogger = LoggerFactory.getLogger(LinuxProxyClient::class.java)

        @JvmStatic
        fun main(args: Array<String>) {
            val packetDumper = PcapNgTcpServerPacketDumper()
            packetDumper.start()

            val client =
                if (args.isEmpty()) {
                    staticLogger.debug("Using default server: 127.0.0.1 $DEFAULT_PORT")
                    val datagramChannel = DatagramChannel.open()
                    datagramChannel.configureBlocking(false)
                    datagramChannel.connect(InetSocketAddress("127.0.0.1", DEFAULT_PORT))
                    LinuxProxyClient(datagramChannel = datagramChannel, packetDumper = packetDumper)
                } else {
                    if (args.size != 2) {
                        staticLogger.warn("Usage: Client <server> <port>")
                        return
                    }
                    val server = args[0]
                    val port = args[1].toInt()
                    val datagramChannel = DatagramChannel.open()
                    datagramChannel.configureBlocking(false)
                    datagramChannel.connect(InetSocketAddress(server, port))
                    LinuxProxyClient(datagramChannel = datagramChannel, packetDumper = packetDumper)
                }
            client.start()

            Signal.handle(Signal("INT")) {
                client.stop()
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

    override fun stop() {
        tunTapDevice.close()
        super.stop()
    }
}
