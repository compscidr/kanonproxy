package com.jasonernst.kanonproxy.tcp

import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v4.Ipv4Header.Companion.packetCounter
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.knet.transport.tcp.TcpHeader.Companion.DEFAULT_WINDOW_SIZE
import com.jasonernst.knet.transport.tcp.options.TcpOption
import com.jasonernst.knet.transport.tcp.options.TcpOptionEndOfOptionList
import com.jasonernst.knet.transport.tcp.options.TcpOptionMaximumSegmentSize
import com.jasonernst.knet.transport.tcp.options.TcpOptionTimestamp
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer

object TcpHeaderFactory {
    private val logger = LoggerFactory.getLogger(javaClass)

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
        isUrg: Boolean = false,
        mss: UShort? = null,
        urgentPointer: UShort = 0u,
        transmissionControlBlock: TransmissionControlBlock? = null,
    ): Packet {
        require(ipHeader.sourceAddress::class == ipHeader.destinationAddress::class) {
            "IP header source and destination addresses must be the same type"
        }

        val options = ArrayList<TcpOption>()
        if (isSyn && mss != null) {
            options.add(TcpOptionMaximumSegmentSize(mss))
            if (transmissionControlBlock!!.sack_permitted) {
                // todo: need to implement this option still
                // options.add(TcpOptionSACKPermitted)
            }
        }

        if (transmissionControlBlock?.send_ts_ok == true) {
            val timeStampOption = TcpOptionTimestamp.maybeTimestamp(tcpHeader)
            val tsecr = timeStampOption?.tsval ?: 0u
            val currentTime = System.currentTimeMillis().toUInt()
            val timeStampResponse =
                if (isAck) {
                    TcpOptionTimestamp(currentTime, tsecr)
                } else {
                    TcpOptionTimestamp(currentTime, 0u)
                }
            options.add(timeStampResponse)
        }
        options.add(TcpOptionEndOfOptionList())

        val sourcePort = if (swapSourceAndDestination) tcpHeader.destinationPort else tcpHeader.sourcePort
        val destinationPort = if (swapSourceAndDestination) tcpHeader.sourcePort else tcpHeader.destinationPort

        // if we want to respond with different options this is the place to do it
        val responseTcpHeader =
            TcpHeader(
                sourcePort = sourcePort,
                destinationPort = destinationPort,
                sequenceNumber = seqNumber,
                acknowledgementNumber = ackNumber,
                windowSize = transmissionControlBlock?.rcv_wnd ?: DEFAULT_WINDOW_SIZE,
                urgentPointer = urgentPointer,
                options = options,
            )

        val payloadCopy = ByteArray(payload.remaining())
        payload.get(payloadCopy)

        responseTcpHeader.setSyn(isSyn)
        responseTcpHeader.setAck(isAck)
        responseTcpHeader.setPsh(isPsh)
        responseTcpHeader.setFin(isFin)
        responseTcpHeader.setRst(isRst)
        responseTcpHeader.setUrg(isUrg)

        val sourceAddress = if (swapSourceAndDestination) ipHeader.destinationAddress else ipHeader.sourceAddress
        val destinationAddress = if (swapSourceAndDestination) ipHeader.sourceAddress else ipHeader.destinationAddress

        val totalLength = (ipHeader.getHeaderLength() + responseTcpHeader.getHeaderLength() + payloadCopy.size.toUInt()).toUShort()

        val responseIpHeader =
            when (sourceAddress) {
                is Inet4Address -> {
                    destinationAddress as Inet4Address
                    Ipv4Header(
                        id = packetCounter.getAndIncrement().toUShort(),
                        sourceAddress = sourceAddress,
                        destinationAddress = destinationAddress,
                        protocol = ipHeader.protocol,
                        totalLength = totalLength,
                    )
                }

                is Inet6Address -> {
                    destinationAddress as Inet6Address
                    Ipv6Header(
                        sourceAddress = sourceAddress,
                        destinationAddress = destinationAddress,
                        protocol = ipHeader.protocol,
                        payloadLength = totalLength,
                    )
                }

                else -> {
                    throw IllegalArgumentException("Unknown IP address type")
                }
            }
        responseTcpHeader.checksum = responseTcpHeader.computeChecksum(responseIpHeader, payloadCopy)
        return Packet(responseIpHeader, responseTcpHeader, payloadCopy)
    }

    /**
     * Given a TCP packet, create an ACK packet with the given ackNumber of how many bytes we
     * are acknowledging we have received.
     *
     * Note: we don't just look at the previous TCP header to determine the ackNumber because it
     * depends on how many bytes we are acknowledging we have received (computed by a TCP state machine
     * or something that is out of the scope of this library).
     *
     * Similarly, the sequence number we send back depends on the current state of the TCP state machine and isn't
     * always based on the ACK number of the previous packet.
     *
     * @param ipHeader the IP header of the packet we are responding to
     * @param tcpHeader the TCP header of the packet we are responding to
     * @param seqNumber the sequence number to use in the response
     * @param ackNumber the acknowledgement number to use in the response
     * @param payload the payload to attach to the ACK (may be empty)
     */
    fun createAckPacket(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        seqNumber: UInt,
        ackNumber: UInt,
        swapSourceAndDestination: Boolean = true,
        payload: ByteBuffer = ByteBuffer.allocate(0),
        isPsh: Boolean = false,
        transmissionControlBlock: TransmissionControlBlock?,
    ): Packet =
        prepareResponseHeaders(
            ipHeader = ipHeader,
            tcpHeader = tcpHeader,
            seqNumber = seqNumber,
            ackNumber = ackNumber,
            swapSourceAndDestination = swapSourceAndDestination,
            payload = payload,
            isAck = true,
            isPsh = isPsh,
            transmissionControlBlock = transmissionControlBlock,
        )

    /**
     * Given an ipHeader, tcpHeader, constructs a FIN packet with the given seq, ack numbers
     */
    fun createFinPacket(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        seqNumber: UInt,
        ackNumber: UInt,
        swapSourceAndDestination: Boolean = true,
        transmissionControlBlock: TransmissionControlBlock?,
    ): Packet =
        prepareResponseHeaders(
            ipHeader = ipHeader,
            tcpHeader = tcpHeader,
            seqNumber = seqNumber,
            ackNumber = ackNumber,
            isFin = true,
            isAck = true,
            swapSourceAndDestination = swapSourceAndDestination,
            transmissionControlBlock = transmissionControlBlock,
        )

    fun createFinPacket(
        sourceAddress: InetAddress,
        destinationAddress: InetAddress,
        sourcePort: UShort,
        destinationPort: UShort,
        seqNumber: UInt,
        ackNumber: UInt,
        swapSourceAndDestination: Boolean = true,
        transmissionControlBlock: TransmissionControlBlock?,
    ): Packet {
        val tcpHeader = TcpHeader(sourcePort = sourcePort, destinationPort = destinationPort)
        val ipHeader =
            if (sourceAddress is Inet4Address) {
                Ipv4Header(
                    sourceAddress = sourceAddress,
                    destinationAddress = destinationAddress as Inet4Address,
                    totalLength =
                        (
                            Ipv4Header.IP4_MIN_HEADER_LENGTH +
                                tcpHeader.getHeaderLength()
                        ).toUShort(),
                    protocol = IpType.TCP.value,
                )
            } else {
                Ipv6Header(
                    sourceAddress = sourceAddress as Inet6Address,
                    destinationAddress = destinationAddress as Inet6Address,
                    payloadLength = tcpHeader.getHeaderLength(),
                    protocol = IpType.TCP.value,
                )
            }
        return createFinPacket(
            ipHeader = ipHeader,
            tcpHeader = tcpHeader,
            seqNumber = seqNumber,
            ackNumber = ackNumber,
            swapSourceAndDestination = swapSourceAndDestination,
            transmissionControlBlock = transmissionControlBlock,
        )
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
        transmissionControlBlock: TransmissionControlBlock? = null,
    ): Packet {
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
            ipHeader = ipHeader,
            tcpHeader = tcpHeader,
            seqNumber = seqNumber,
            ackNumber = ackNumber,
            swapSourceAndDestination = true,
            isRst = true,
            transmissionControlBlock = transmissionControlBlock,
        )
    }

    /**
     * This is only used for tests, the OS creates the SYN packets, not us.
     *
     * NB: the source and destination should not be swapped when we create the SYN packet since
     * we are providing a previous packet from the other side to copy from.
     *
     * Technically the SYN packet supports payloads, but we don't use them here.
     *
     * @param sourceAddress the source address of the SYN packet
     * @param destinationAddress the destination address of the SYN packet
     * @param sourcePort the source port of the SYN packet
     * @param destinationPort the destinationPort
     * @param startingSeq the sequence number to start the TCP session with
     */
    fun createSynPacket(
        sourceAddress: InetAddress,
        destinationAddress: InetAddress,
        sourcePort: UShort,
        destinationPort: UShort,
        startingSeq: UInt,
        mss: UShort,
        transmissionControlBlock: TransmissionControlBlock,
    ): Packet {
        transmissionControlBlock.send_ts_ok = true
        transmissionControlBlock.iss = startingSeq
        transmissionControlBlock.snd_nxt = startingSeq + 1u
        transmissionControlBlock.snd_una.value = startingSeq
        val tcpHeader = TcpHeader(sourcePort, destinationPort, startingSeq, 0u)

        val ipHeader =
            IpHeader.createIPHeader(
                sourceAddress,
                destinationAddress,
                IpType.TCP,
                tcpHeader.getHeaderLength().toInt(),
            )

        return prepareResponseHeaders(
            ipHeader = ipHeader,
            tcpHeader = tcpHeader,
            seqNumber = startingSeq,
            ackNumber = 0u,
            swapSourceAndDestination = false,
            isSyn = true,
            mss = mss,
            transmissionControlBlock = transmissionControlBlock,
        )
    }

    /**
     * Given a SYN packet, create a SYN-ACK packet to send back to the client. Note the IP and TCP
     * source / destination returned will be returned swapped from those sent to this function.
     *
     * The sequence number will be randomly generated. The acknowledgement number will be the the
     * previously received sequence number + 1
     * (see https://datatracker.ietf.org/doc/html/rfc793#section-3.2)
     *
     * NB: While TCP supports sending data in the SYN packet, we do not for now.
     *
     * @param ipHeader the IP header of the SYN packet
     * @param tcpHeader the TCP header of the SYN packet
     *
     * @return A Packet with the SYN-ACK packet encapsulated in the IP and TCP headers
     */
    fun createSynAckPacket(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        mss: UShort,
        transmissionControlBlock: TransmissionControlBlock,
    ): Packet {
        require(tcpHeader.isSyn()) { "Cannot create SYN-ACK packet for non-SYN packet" }
        // use a random sequence number because we're just starting the session
        // todo: probably update this to not be random using this approach:
        //   pg: 27 https://datatracker.ietf.org/doc/html/rfc793
        // To avoid confusion we must prevent segments from one incarnation of a
        //  connection from being used while the same sequence numbers may still
        //  be present in the network from an earlier incarnation.  We want to
        //  assure this, even if a TCP crashes and loses all knowledge of the
        //  sequence numbers it has been using.  When new connections are created,
        //  an initial sequence number (ISN) generator is employed which selects a
        //  new 32 bit ISN.  The generator is bound to a (possibly fictitious) 32
        //  bit clock whose low order bit is incremented roughly every 4
        //  microseconds.  Thus, the ISN cycles approximately every 4.55 hours.
        //  Since we assume that segments will stay in the network no more than
        //  the Maximum Segment Lifetime (MSL) and that the MSL is less than 4.55
        //  hours we can reasonably assume that ISN's will be unique.
        return prepareResponseHeaders(
            ipHeader,
            tcpHeader,
            transmissionControlBlock.iss,
            transmissionControlBlock.rcv_nxt,
            true,
            ByteBuffer.allocate(0),
            isSyn = true,
            isAck = true,
            isPsh = false,
            isFin = false,
            isRst = false,
            isUrg = false,
            mss = mss,
            transmissionControlBlock = transmissionControlBlock,
        )
    }
}
