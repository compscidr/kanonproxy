package com.jasonernst.kanonproxy.icmp

import com.jasonernst.icmp.common.v4.IcmpV4DestinationUnreachableCodes
import com.jasonernst.knet.datalink.EthernetHeader
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.nextheader.NextHeader
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.knet.transport.tcp.options.TcpOptionMaximumSegmentSize
import com.jasonernst.packetdumper.filedumper.TextFilePacketDumper
import com.jasonernst.packetdumper.stringdumper.StringPacketDumper
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.slf4j.LoggerFactory
import java.io.FileNotFoundException
import java.net.InetAddress
import java.nio.ByteBuffer

class IcmpFactoryTest {
    private val logger = LoggerFactory.getLogger(javaClass)

    @Test fun ipv4DestinationUnreachable() {
        val filename = "/test_packets/ipV4TcpSyn.dump"
        val resource =
            javaClass.getResource(filename)
                ?: throw FileNotFoundException("Could not find test dump: $filename")
        val stream = TextFilePacketDumper.parseFile(resource.file, true)
        logger.debug("Read buffer length: {}", stream.limit())

        // get rid of the eth header
        EthernetHeader.fromStream(stream)

        val ipHeader = IpHeader.fromStream(stream)
        logger.debug("IP header: {}", ipHeader)

        assertEquals(IpType.TCP.value, ipHeader.getNextHeaderProtocol())
        val nextHeader = NextHeader.fromStream(ipHeader, stream)
        assertTrue(nextHeader is TcpHeader)

        val tcpHeader = nextHeader as TcpHeader
        logger.debug("TCP header: {}", tcpHeader)

        val destinationUnreachablePacket =
            IcmpFactory.createDestinationUnreachable(
                IcmpV4DestinationUnreachableCodes.HOST_UNREACHABLE,
                InetAddress.getByName("127.0.0.1"),
                ipHeader,
                tcpHeader,
                ByteArray(0),
                TcpOptionMaximumSegmentSize.defaultIpv4MSS.toInt(),
            )

        val stringPacketDumper = StringPacketDumper(logger)
        stringPacketDumper.dumpBuffer(ByteBuffer.wrap(destinationUnreachablePacket.toByteArray()))

        // regression test that we don't accidentally super pad the packet
        assertEquals(8, destinationUnreachablePacket.toByteArray().last())
    }
}
