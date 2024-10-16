package com.jasonernst.kanonproxy

import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.knet.transport.tcp.options.TcpOption
import com.jasonernst.knet.transport.tcp.options.TcpOptionEndOfOptionList
import com.jasonernst.knet.transport.tcp.options.TcpOptionMaximumSegmentSize
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicInteger

object TcpHeaderFactory {
    val packetCounter: AtomicInteger = AtomicInteger(0)
    /**
     * Performs a bunch of common steps regardless of the response:
     * 1. Copies the headers so we still have the originals
     * 2. Sets the Flags
     * 2. Sets the SEQ and ACK numbers
     * 3. optionally swaps source and dest addresses and ports
     * 4. computes the checksum
     * 5. returns the packet
     * @param ipHeader the IP header to base the response from
     * @param transportHeader the transport header to base the response from
     * @param seqNumber the sequence number to set in the response
     * @param ackNumber the acknowledgement number to set in the response
     * @param swapSourceAndDestination whether to swap the source and destination addresses and
     * ports
     * @param payload the payload to include in the response and use for checksum calculation
     *  can use ByteBuffer.allocate(0) if no payload
     *
     *  NB: at the end of this, the payload position is set to payload.limit()
     */
    fun prepareResponseHeaders(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        seqNumber: UInt,
        ackNumber: UInt,
        swapSourceAndDestination: Boolean = true,
        payload: ByteBuffer = ByteBuffer.allocate(0),
        isSyn: Boolean = false,
        isAck: Boolean = false,
        isPsh: Boolean = false,
        isFin: Boolean = false,
        isRst: Boolean = false,
        mss: UShort = 0u,
    ): Packet {
        require(ipHeader.sourceAddress::class == ipHeader.destinationAddress::class) {
            "IP header source and destination addresses must be the same type"
        }

        // can't copy the TCP header directly otherwise we have to clear the options and we wind
        // up getting ConcurrentModificationExceptions
        // set the MSS to be the buffer size - BumpHeader size
        val options = ArrayList<TcpOption>()
        if (isSyn) {
            options.add(TcpOptionMaximumSegmentSize(mss))
        }
        options.add(TcpOptionEndOfOptionList())

        var optionSize = 0
        for (option in options) {
            optionSize += option.size.toInt()
        }

        // if we want to respond with different options this is the place to do it
        val responseTcpHeader =
            TcpHeader(
                sourcePort = tcpHeader.sourcePort,
                destinationPort = tcpHeader.destinationPort,
                sequenceNumber = seqNumber,
                acknowledgementNumber = ackNumber,
                windowSize = tcpHeader.windowSize,
                urgentPointer = tcpHeader.urgentPointer,
                options = options,
            )

        val payloadCopy = ByteArray(payload.remaining())
        payload.get(payloadCopy)

        responseTcpHeader.setSyn(isSyn)
        responseTcpHeader.setAck(isAck)
        responseTcpHeader.setPsh(isPsh)
        responseTcpHeader.setFin(isFin)
        responseTcpHeader.setRst(isRst)

        val responseIpHeader = if (swapSourceAndDestination) {
            if (ipHeader is Ipv4Header) {
                Ipv4Header(
                    id = packetCounter.getAndIncrement().toUShort(),
                    sourceAddress = ipHeader.destinationAddress,
                    destinationAddress = ipHeader.sourceAddress,
                    protocol = ipHeader.protocol,
                    totalLength = (ipHeader.getHeaderLength() + responseTcpHeader.getHeaderLength() + payloadCopy.size.toUShort()).toUShort(),
                )
            } else {
                Ipv6Header(
                    sourceAddress = ipHeader.destinationAddress,
                    destinationAddress = ipHeader.sourceAddress,
                    protocol = ipHeader.protocol,
                    payloadLength = (ipHeader.getHeaderLength() + responseTcpHeader.getHeaderLength() + payloadCopy.size.toUShort()).toUShort(),
                )
            }
        } else {
            if (ipHeader is Ipv4Header) {
                Ipv4Header(
                    id = packetCounter.getAndIncrement().toUShort(),
                    sourceAddress = ipHeader.sourceAddress,
                    destinationAddress = ipHeader.destinationAddress,
                    protocol = ipHeader.protocol,
                    totalLength = (ipHeader.getHeaderLength() + responseTcpHeader.getHeaderLength() + payloadCopy.size.toUShort()).toUShort(),
                )
            } else {
                Ipv6Header(
                    sourceAddress = ipHeader.sourceAddress,
                    destinationAddress = ipHeader.destinationAddress,
                    protocol = ipHeader.protocol,
                    payloadLength = (ipHeader.getHeaderLength() + responseTcpHeader.getHeaderLength() + payloadCopy.size.toUShort()).toUShort(),
                )
            }
        }

        responseTcpHeader.checksum =
            computeChecksum(
                responseIPHeader,
                responseTcpHeader,
                ByteBuffer.wrap(payloadCopy),
                false,
            )
        computeChecksum(
            responseIPHeader,
            responseTcpHeader,
            ByteBuffer.wrap(payloadCopy),
            true,
        )

        return BumpPacket(responseIPHeader, responseTcpHeader, payloadCopy)
    }

    /**
     * Given the last received packet from the client, create an RST packet to reset the connection.
     *
     * This is typically for when something went wonky and we need the other side to start again.
     *
     * Note the seq number must be the next expected seq number for the client based on the last
     * packet, or it won't take effect: https://www.rfc-editor.org/rfc/rfc5961#section-3.2
     *
     * This is because there is an attack where you could force resets without this.
     */
    fun createRstPacket(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
    ): Packet {
        require(ipHeader.sourceAddress::class == ipHeader.destinationAddress::class) {
            "IP header source and destination addresses must be the same type"
        }

        // page 36: RFC 793 https://datatracker.ietf.org/doc/html/rfc793#section-3.2
        // If the incoming segment has an ACK field, the reset takes its
        //    sequence number from the ACK field of the segment, otherwise the
        //    reset has sequence number zero and the ACK field is set to the sum
        //    of the sequence number and segment length of the incoming segment.
        //    The connection remains in the CLOSED state.
        val ackNumber: UInt
        val seqNumber: UInt

        // see page 64
        if (tcpHeader.isAck()) {
            seqNumber = tcpHeader.acknowledgementNumber
            ackNumber = 0u
        } else {
            seqNumber = 0u
            ackNumber = tcpHeader.sequenceNumber + ipHeader.getPayloadLength().toUInt() -
                    tcpHeader.getHeaderLength().toUInt()
        }

        return prepareResponseHeaders(
            ipHeader,
            tcpHeader,
            seqNumber,
            ackNumber,
            swapSourceAndDestination = true,
            isRst = true,
        )
    }
}