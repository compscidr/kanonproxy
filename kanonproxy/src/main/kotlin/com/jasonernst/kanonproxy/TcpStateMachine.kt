package com.jasonernst.kanonproxy

import com.jasonernst.icmp_common.v4.ICMPv4DestinationUnreachableCodes
import com.jasonernst.icmp_common.v6.ICMPv6DestinationUnreachableCodes
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.knet.transport.tcp.TcpHeader.Companion.DEFAULT_WINDOW_SIZE
import org.slf4j.LoggerFactory
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentLinkedQueue
import kotlin.jvm.java
import kotlin.jvm.javaClass
import kotlin.ranges.until
import kotlin.toUInt

/**
 * Abstracts the TCP state machine out of the InternetTcpSession so it can be used by both the
 * InternetTcpSession and the TCPLightSession. Then have each class focused on their specific
 * directional behavior + managing channels / sockets.
 *
 * Assumes that the remote side is already connected and we are just managing the TCP session.
 * Previously, we had remote connection state in here, but it has since shifted into the
 * VPNClientPacketHandler's responsibility. If the remote side is not connected, the session
 * should enqueue the incoming packets until the connection is made, and then process them during
 * the notifyRemoteConnected() call.
 */
class TcpStateMachine(var tcpState: TcpState, val mtu: UShort) {
    private val logger = LoggerFactory.getLogger(javaClass)

    // sequence and ack numbers for the TCP session
    // see: https://datatracker.ietf.org/doc/html/rfc793#section-3.7
    // also see: https://datatracker.ietf.org/doc/html/rfc793#section-3.2
    private var initialSendSequence = 0u // ISS
    var sendNext = 0u // SND.NEXT
    var sendUnacknowledged = 0u // SND.UNA
    var recvNext = 0u // RCV.NEXT
    private var initialRecvSequence = 0u // IRS
    private var sendUrgentPointer = 0u // SND.UP

    // set to true when a PSH was received so we can register interest in channel writes
    // and wakeup the selector
    var pshReceived = false

    var mss: UShort = 0u // MSS, var to make tests easier
    var sendWindow = DEFAULT_WINDOW_SIZE // SND.WND, var to make tests easier
    var sendWindowUpdateSequence = 0u // SND.WL1, var to make tests easier
    var sendWindowUpdateAck = 0u // SND.WL2, var to make tests easier
    var recvWindow = DEFAULT_WINDOW_SIZE // RCV.WND, var to make tests easier
    private var recvUrgentPointer = 0u // RCV.UP

    private val srtt = 0u // SRTT smoothed round trip time

    var retransmitQueue = ConcurrentLinkedQueue<Packet>() // var to make tests easier

    // set when we send out FIN so we know whether we've received an ACK for it or not.
    var timeWaitTime = 0L
    var finSeq = 0u
    private var finHasBeenAcked = false
    var isClosed = false

    /**
     * Given the current state of the session, this method will use the incoming packet headers
     * and the payload to determine the next state, and then return the appropriate packet(s) to
     * be enqueued to be sent back to the VPN client. More than one packet may be returned in some
     * cases, such as if there is data + a FIN packet (we could do fancier stuff where we try to
     * determine if the session is ending and then just toggle the FIN flag on for the last packet
     * but its easier just to enqueue a FIN packet separately and send one more).
     *
     * It will leave the payload stream at:
     *   position + ipHeader.getPayloadLength() - tcpHeader.getHeaderLength()
     *
     */
    fun processHeaders(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        payload: ByteArray,
        session: Session,
    ): List<Packet> {
        logger.trace("Handling STATE: {} for session: {}", tcpState, session)
        when (tcpState) {
            TcpState.CLOSED -> {
                return handleClosedState(ipHeader, tcpHeader)
            }
            TcpState.LISTEN -> {
                return handleListenState(ipHeader, tcpHeader)
            }
            TcpState.SYN_SENT -> {
                logger.error("Received packet in SYN_SENT state, but we don't support that state yet, enqueuing RST: $this")
                return listOf(
                    TcpHeaderFactory.createRstPacket(
                        ipHeader,
                        tcpHeader
                    )
                )
            }
            TcpState.SYN_RECEIVED -> {
                return handleSynReceivedState(ipHeader, tcpHeader, session)
            }
            TcpState.ESTABLISHED -> {
                return handleEstablishedState(ipHeader, tcpHeader, payload, session)
            }
            TcpState.FIN_WAIT_1 -> {
                return handleFinWait1State(ipHeader, tcpHeader, payload, session)
            }
            TcpState.FIN_WAIT_2 -> {
                return handleFinWait2State(ipHeader, tcpHeader, payload, session)
            }
            TcpState.CLOSING -> {
                return handleClosingState(ipHeader, tcpHeader, payload, session)
            }
            TcpState.CLOSE_WAIT -> {
                return handleCloseWaitState(ipHeader, tcpHeader, payload, session)
            }
            TcpState.TIME_WAIT -> {
                return handleTimeWaitState(ipHeader, tcpHeader, session)
            }
            TcpState.LAST_ACK -> {
                return handleLastAckState(ipHeader, tcpHeader)
            }
        }
    }

    /**
     * We probably shouldn't receive any packets in this state, but its included for completeness.
     */
    private fun handleClosedState(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
    ): List<Packet> {
        // page 36: https://datatracker.ietf.org/doc/html/rfc793#section-3.2
        // "If the connection does not exist (CLOSED) then a reset is sent
        //    in response to any incoming segment except another reset.  In
        //    particular, SYNs addressed to a non-existent connection are rejected
        //    by this means."

        // page 65: An incoming segment containing a RST is discarded.
        if (TcpHeader.isRst()) {
            logger.error("Got RST in CLOSED state, ignoring: $this")
            return emptyList()
        }

        logger.error("Received packet in CLOSED state. Enqueuing RST: $this")
        return listOf(
            TcpHeaderFactory.createRstPacket(
                ipHeader,
                tcpHeader
            )
        )
    }

    /**
     * The goal here is to receive a SYN packet from the client, and send a SYN-ACK back to them.
     */
    fun handleListenState(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
    ): List<Packet> {
        // page 65: An incoming segment containing a RST is discarded.
        if (TcpHeader.isRst()) {
            logger.error("Got RST in LISTEN state, ignoring: $this")
            return emptyList()
        }
        // page 36: https://datatracker.ietf.org/doc/html/rfc793#section-3.2
        // "If the connection is in any non-synchronized state (LISTEN,
        //    SYN-SENT, SYN-RECEIVED), and the incoming segment acknowledges
        //    something not yet sent (the segment carries an unacceptable ACK), or
        //    if an incoming segment has a security level or compartment which
        //    does not exactly match the level and compartment requested for the
        //    connection, a reset is sent."
        // pg 64: Any acknowledgment is bad if it arrives on a connection still in
        //        the LISTEN state.  An acceptable reset segment should be formed
        //        for any arriving ACK-bearing segment
        if (TcpHeader.isAck()) {
            logger.error("Received ACK in LISTEN state. Enqueuing RST moving to CLOSED state: $this")
            tcpState = TcpState.CLOSED
            isClosed = true
            val dummyBuffer = ByteBuffer.allocate(UShort.toInt())
            dummyBuffer.put(IpHeader.toByteArray())
            dummyBuffer.put(TcpHeader.toByteArray())
            dummyBuffer.flip()
            // logger.trace("PACKET: ${BufferUtil.toHexString(dummyBuffer, 0, dummyBuffer.limit())}")
            return listOf(
                TcpHeaderFactory.createRstPacket(
                    ipHeader,
                    tcpHeader
                )
            )
        }
        return if (TcpHeader.isSyn()) {
            retransmitQueue.clear() // just to be sure we start in a fresh state

            var foundMSS = false
            for (option in TcpHeader.getOptions()) {
                if (option is xyz.bumpapp.transport.tcp.TCPOptionMaximumSegmentSize) {
                    foundMSS = true
                    // assuming the client MSS is already taking into account the reduction of the
                    // MTU - BUMP, IP, UDP headers via the MTU call on the construction of the VPN
                    // android client. TODO: make sure the same is true with the standalone stuff
                    // logger.debug("MSS proposed by client: ${option.mss}")

                    val serverMSS = UInt.toUShort()
                    // logger.debug("MSS proposed by server: $serverMSS")

                    mss =
                        if (serverMSS compareTo xyz.bumpapp.transport.tcp.TCPOptionMaximumSegmentSize.mss) {
                            serverMSS
                        } else {
                            xyz.bumpapp.transport.tcp.TCPOptionMaximumSegmentSize.mss
                        }
                    logger.debug("Using MSS: $mss")
                }
            }
            if (!foundMSS) {
                logger.error("Didn't find an MSS option in the SYN packet, enqueuing RST: $this")
                return listOf(
                    TcpHeaderFactory.createRstPacket(
                        ipHeader,
                        tcpHeader
                    )
                )
            }
            logger.trace("Got SYN from client while in LISTEN state")

            val response = TcpHeaderFactory.createSynAckPacket(
                ipHeader,
                tcpHeader,
                mss
            )
            val responseTCPHeader = Packet.ipNextHeader as TcpHeader
            logger.trace(
                "Enqueuing SYN-ACK to client with Seq:" +
                    " ${UInt.toLong()}, " +
                    "ACK: ${UInt.toLong()} " +
                    "${Packet.ipHeader} $responseTCPHeader: $this",
            )
            initialRecvSequence = TcpHeader.sequenceNumber
            initialSendSequence = TcpHeader.sequenceNumber
            sendNext = initialSendSequence + 1u
            recvNext = TcpHeader.sequenceNumber + 1u
            sendUnacknowledged = initialSendSequence
//            logger.trace(
//                "Session sendNext: ${Integer.toUnsignedString(
//                    sendNext.toInt(),
//                )} recvNext: $recvNext. Changing state to SYN_RECEIVED: $this",
//            )
            tcpState = TcpState.SYN_RECEIVED
            listOf(response)
        } else {
            // from page 65: Any other control or text-bearing segment (not containing SYN)
            //        must have an ACK and thus would be discarded by the ACK
            //        processing.  An incoming RST segment could not be valid, since
            //        it could not have been sent in response to anything sent by this
            //        incarnation of the connection.  So you are unlikely to get here,
            //        but if you do, drop the segment, and return.
            logger.error(
                "Got unexpected TCP flag: $tcpHeader when in LISTEN state, " +
                    "Enqueuing RST: $this",
            )
            return listOf(
                TcpHeaderFactory.createRstPacket(
                    ipHeader,
                    tcpHeader
                )
            )
        }
    }

    /**
     * The goal here is to receive the ACK from the previously sent SYN-ACK we sent to get into
     * this state.
     */
    private fun handleSynReceivedState(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        session: xyz.bumpapp.vpn.server.session.TransportSession,
    ): List<Packet> {
        // page 69, lists states which should do this check first and return and ACK and drop
        // the segment, unless the RST bit is set.
        if (!isInWindow(ipHeader, tcpHeader) && !TcpHeader.isRst()) {
            return listOf(
                TcpHeaderFactory.createACKPacket(
                    ipHeader,
                    tcpHeader,
                    sendNext,
                    recvNext
                )
            )
        }
        if (TcpHeader.isRst()) {
            // Page 37:  If the receiver was
            //  in SYN-RECEIVED state and had previously been in the LISTEN state,
            //  then the receiver returns to the LISTEN state.

            // However, LISTEN state only makes sense for us when we are first setting up the
            // connection. If this is true, the stream will have proper SYN packets coming so we
            // can close this attempt at the session and retry when we received the next SYN packet.
            logger.error("Got RST from client while in $tcpState state, closing connection: $this")
            tcpState = TcpState.CLOSED
            isClosed = true
            return emptyList()
        }
        if (TcpHeader.isSyn()) {
            // page 71: If the SYN is in the window it is an error, send a reset, any
            //        outstanding RECEIVEs and SEND should receive "reset" responses,
            //        all segment queues should be flushed, the user should also
            //        receive an unsolicited general "connection reset" signal, enter
            //        the CLOSED state, delete the TCB, and return.
            //
            //        If the SYN is not in the window this step would not be reached
            //        and an ack would have been sent in the first step (sequence
            //        number check).
            return listOf(
                TcpHeaderFactory.createRstPacket(
                    ipHeader,
                    tcpHeader
                )
            )
        }
        if (!TcpHeader.isAck()) {
            // page 72: If the ACK bit is off, drop the segment and return.
            logger.warn("Got non-ACK packet in $tcpState state, ignoring: $this")
            return emptyList()
        } else {
            return if (TcpHeader.acknowledgementNumber contains sendUnacknowledged..sendNext) {
                // page 72: If the ACK acknowledges our SYN-ACK then enter ESTABLISHED
                //        state and return.
//                logger.trace(
//                    "Got ACK from client while in SYN_RECEIVED state, changing state to " +
//                        "ESTABLISHED: $this",
//                )
                tcpState = TcpState.ESTABLISHED

                removeAckedPacketsFromRetransmit()

                // page 75: check for FIN bit, and if set, move to CLOSE-WAIT state
                if (TcpHeader.isFin()) {
                    recvNext++
//                    logger.trace(
//                        "Got FIN from client while in ESTABLISHED (just after SYN)" +
//                            " state, changing state to CLOSE_WAIT: $this",
//                    )
                    tcpState = TcpState.CLOSE_WAIT
                    if (session is xyz.bumpapp.vpn.server.session.InternetTCPSession) {
                        xyz.bumpapp.vpn.server.session.InternetSession.isVPNClientAborting = true
                    }

                    if (session is xyz.bumpapp.vpn.server.session.InternetTCPSession) {
                        return TcpHeaderFactory.encapsulateSessionBuffer(
                            session
                        )
                    } else {
                        // todo: figure out how to handle this for the light session
                    }
                }

                emptyList()
            } else {
                // page 72: If the ACK is not acceptable then form a reset segment,
                //        enter the CLOSED state, delete the TCB, and return.
                logger.error(
                    "Got ACK from client while in SYN_RECEIVED state, but ACK was not " +
                        "acceptable. Enqueuing RST: $this",
                )
                listOf(
                    TcpHeaderFactory.createRstPacket(
                        ipHeader,
                        tcpHeader
                    )
                )
            }
        }
    }

    /**
     * See page 53 of RFC 793: https://tools.ietf.org/html/rfc793#page-53
     * "A natural way to think about processing incoming segments is to
     *    imagine that they are first tested for proper sequence number (i.e.,
     *    that their contents lie in the range of the expected "receive window"
     *    in the sequence number space) and then that they are generally queued
     *    and processed in sequence number order."
     *
     * Page 69, spells out 4 tests for accepting a packet
     *
     * According to page 82, TCP considers packets in the range RCV.NEXT to RCV.NEXT + RCV.WND - 1
     * carrying acceptable data or control. Segments containing sequence numbers entirely outside
     * of this range are considered duplicates and discarded.
     */
    fun isInWindow(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
    ): Boolean {
        val recvWindowMax = recvNext + toUInt()
        logger.trace("RECV window from $recvNext to $recvWindowMax: $tcpHeader")
        logger.trace("$tcpHeader")
        val segmentLength = IpHeader.getPayloadLength() - TcpHeader.getHeaderLength()
        logger.trace(
            "TCP SEQ START: ${TcpHeader.sequenceNumber} END: " +
                "${TcpHeader.sequenceNumber + segmentLength}",
        )
        if (segmentLength equals 0u) {
            return if (recvWindow equals UInt.toUShort()) {
                if (TcpHeader.sequenceNumber equals recvNext) {
                    true
                } else {
                    logger.warn(
                        "SequenceNumberNotInWindow: Segment length is 0, recvWindow is 0." +
                            " Got packet with sequence number " +
                            "${TcpHeader.sequenceNumber} but expected $recvNext: $this",
                    )
                    false
                }
            } else {
                if (TcpHeader.sequenceNumber contains recvNext until recvWindowMax) {
                    true
                } else if (TcpHeader.sequenceNumber compareTo (UInt.Companion.MAX_VALUE - recvWindow)) {
                    /**
                     * Rollover error was found when a tcpEchoSessionTest was created for a
                     * sequence number when
                     *      UInt.MAX_VALUE - UShort.MAX_VALUE <= Sequence Number < UInt.MAX_VALUE
                     * This occurred due to the recvWindowMax being between 0 and UShort.MAX_VALUE
                     * while the sequence number
                     * still hadn't rolled over and thus was checking improperly.
                     * @author Patrick Houlding
                     */
                    logger.debug(
                        "recvWindowMax rollover encountered. tcpHeader Sequence Number is within" +
                            " UShort.MAX_VALUE of UInt.MAX_VALUE",
                    )
                    true
                } else {
                    logger.warn(
                        "SequenceNumberNotInWindow: Segment length is 0, but sequence number" +
                            " ${TcpHeader.sequenceNumber} is not in window from $recvNext to $recvWindowMax: $this",
                    )
                    false
                }
            }
        } else {
            return if (recvWindow equals UInt.toUShort()) {
                logger.warn(
                    "SequenceNumberNotInWindow: recvWindow is 0, so we are not accepting" +
                        " any data packets, just control: $this",
                )
                false
            } else {
                val segmentEnd = (TcpHeader.sequenceNumber + segmentLength) - 1U

                // Check left bound before rollback & within Short window
                if (TcpHeader.sequenceNumber compareTo (UInt.Companion.MAX_VALUE - recvWindow)) {
                    // recvWindowMax has rolled over and seq# hasn't
                    if (TcpHeader.sequenceNumber contains recvNext until UInt.Companion.MAX_VALUE) {
                        // tcpHeader before rollover and inside left bound, now check segmentEnd
                        if (segmentEnd compareTo recvWindowMax || segmentEnd compareTo (
                                UInt.Companion.MAX_VALUE -
                                    recvWindow
                            )
                        ) {
                            // segment end either before rollover or before window max (right bound)
                            // This final line checks the C9 case (starting before rollover
                            // but ending after, inside recvWindow)
                            if (TcpHeader.sequenceNumber compareTo (UInt.Companion.MAX_VALUE - recvWindow) &&
                                recvNext compareTo recvWindow
                            ) {
                                logger.warn(
                                    "SequenceNumberNotInWindow: Sequence number is" +
                                        " before recv window",
                                )
                                false
                            } else {
                                true
                            }
                        } else {
                            logger.warn(
                                "SequenceNumberNotInWindow: TCP Sequence number is " +
                                    "within range but the Segment end is not",
                            )
                            false
                        }
                    } else {
                        // TODO: check if recvNext could ever rollback here..?
                        logger.warn(
                            "SequenceNumberNotInWindow: TCP Sequence number is between " +
                                "recvWindow and UInt max, but is before recvNext",
                        )
                        false
                    }
                } else {
                    // Seq# is before the UShort window, therefore check left & right bound simply
                    // First check if there is a weird rollback on recvNext - 1U but not on the seq#
                    if (recvNext - 1U compareTo (UInt.Companion.MAX_VALUE - recvWindow) &&
                        TcpHeader.sequenceNumber compareTo recvWindow
                    ) {
                        if (segmentEnd compareTo recvWindowMax) {
                            true
                        } else {
                            logger.warn(
                                "SequenceNumberNotInWindow: TCP Sequence NUmber is " +
                                    "within range but the segment end is not",
                            )
                            false
                        }
                    } else {
                        // No weird rollbacks, simplest case here
                        if (TcpHeader.sequenceNumber contains recvNext until recvWindowMax &&
                            segmentEnd contains recvNext - 1U until recvWindowMax
                        ) {
                            true
                        } else {
                            logger.warn(
                                "SequenceNumberNotInWindow, no rollbacks but is out " +
                                    "of range SEQ: {}, SEGMENT END: {} RECVNEXT: {}, RECVWINDOWMAX: {}",
                                TcpHeader.sequenceNumber,
                                segmentEnd,
                                recvNext,
                                recvWindowMax,
                            )
                            false
                        }
                    }
                }
            }
        }
    }

    /**
     * Update send window (prevent old segments from updating the window)
     * From: https://datatracker.ietf.org/doc/html/rfc793#page-72
     *
     * If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK)),
     * set SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
     *
     * Note that SND.WND is an offset from SND.UNA, that SND.WL1
     * records the sequence number of the last segment used to update
     * SND.WND, and that SND.WL2 records the acknowledgment number of
     * the last segment used to update SND.WND.  The check here
     * prevents using old segments to update the window.
     *
     * sendWindow = SND.WND
     * sendWindowUpdateSequence = SND.WL1
     * sendWindowUpdateAck = SND.WL2
     *
     * To make this function more clear, we can either update the send window on 1) a newer
     * sequence number than the last time we updated (ie: SND.WL1). Otherwise we can update if
     * we get an ACK for the SND.WL1 and we're receiving a newer ACK than the last time we updated
     * via an ACK (SND.WL2).
     *
     * Moved into a function for testability.
     */
    fun sendWindowUpdate(tcpHeader: TcpHeader) {
        // first: check if the sequence number is newer than the sequence number when we last
        // updated the window
        if (sendWindowUpdateSequence compareTo TcpHeader.sequenceNumber ||
            // otherwise check if the last time we updated the window was the packet we're waiting
            // for an ACK from, and the ACK packet update sequence is newer
            (
                sendWindowUpdateSequence equals sendUnacknowledged &&
                    sendWindowUpdateAck compareTo TcpHeader.acknowledgementNumber
            )
        ) {
            sendWindow = TcpHeader.windowSize
            sendWindowUpdateSequence = TcpHeader.sequenceNumber
            sendWindowUpdateAck = TcpHeader.acknowledgementNumber
//            logger.trace(
//                "ADJUSTING SEND WINDOW: sendWindow: $sendWindow, sendWindowUpdateSequence: " +
//                    "$sendWindowUpdateSequence, sendWindowUpdateAck: " +
//                    "$sendWindowUpdateAck, SND.UNA: $sendUnacknowledged",
//            )
        }
    }

    /**
     * Page 72: ESTABLISHED STATE
     *
     * Not private for testing purposes.
     */
    fun establishedProcessAck(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
    ): Packet? {
        if (TcpHeader.acknowledgementNumber contains (sendUnacknowledged + 1u)..sendNext) {
            sendUnacknowledged = TcpHeader.acknowledgementNumber

            removeAckedPacketsFromRetransmit()
            sendWindowUpdate(tcpHeader)
        } else if (TcpHeader.acknowledgementNumber compareTo sendUnacknowledged) {
            // page 72: If the ACK is a duplicate (the sequence number of the
            //        segment acknowledged is below SND.UNA) then it can be
            //        ignored.
            logger.warn("Got duplicate ACK from client, ignoring: $tcpHeader")
        } else if (TcpHeader.acknowledgementNumber compareTo sendNext) {
            // page 72: If the ACK acknowledges something not yet sent (the
            //        acknowledgment number is above SND.NXT) then send an ACK,
            //        drop the segment, and return.
            logger.warn(
                "Got ACK from client which acknowledges something not yet sent," +
                    " ignoring: $tcpHeader",
            )
            return TcpHeaderFactory.createACKPacket(
                ipHeader,
                tcpHeader,
                sendNext,
                recvNext
            )
        }
        return null
    }

    /**
     * process the segment text (page 74)
     *
     * move the received payload into the buffer from Internet to VPN client
     */
    private fun processText(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        payload: ByteArray,
        session: xyz.bumpapp.vpn.server.session.TransportSession,
    ): Packet? {
        // todo: use the remaining recv buffer capacity to limit how much is actually accepted
        // https://linear.app/bumpapp/issue/BUMP-310/tcp-adjust-the-recv-window
        // and return a response with the window size + the amount of data accepted remaining
        // constant (reduce the window size by the difference between the amount of data
        // accepted and the amount of data in the segment)
        // see page 74
        val payloadSize = IpHeader.getPayloadLength() - TcpHeader.getHeaderLength()
        if (payloadSize compareTo 0u) {
            if (session is xyz.bumpapp.vpn.server.session.InternetTCPSession) {
                xyz.bumpapp.vpn.server.session.InternetTCPSession.addPayloadForInternet(
                    payload,
                    UInt.toInt()
                )
            } else {
                // todo: figure out what to do here for TCPLightSession
            }
//            logger.trace(
//                "recvNext: $recvNext, adding $payloadSize bytes to buffer, new " +
//                    "recvNext: ${(recvNext + payloadSize)}: $tcpHeader",
//            )
            recvNext = recvNext + toUInt() -
                    toUInt()
            if (TcpHeader.isPsh()) {
                pshReceived = true
            }
            val dataAck = TcpHeaderFactory.createACKPacket(
                ipHeader,
                tcpHeader,
                sendNext,
                recvNext
            )
            // logger.trace("Got: $tcpHeader \nSending back: ${dataAck.ipNextHeader}: $tcpHeader")
            return dataAck
        }
        return null
    }

    /**
     * Performs a few common basic checks. If any check fails the response Packet will be non-null.
     * There are some states which handle close to this but have special state changes, so they
     * might not be able to re-use this code as is.
     */
    private fun basicChecks(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
    ): Packet? {
        // page 69, lists states which should do this check first and return and ACK and drop
        // the segment, unless the RST bit is set.
        // todo: debug whats up here
        // https://linear.app/bumpapp/issue/BUMP-309/determine-why-isinwindow-is-often-reporting-out-of-window-packets
        if (!isInWindow(ipHeader, tcpHeader) && !TcpHeader.isRst()) {
            logger.warn("NOT IN WINDOW! ACK-ing and dropping segment: $tcpHeader")
            return TcpHeaderFactory.createACKPacket(
                ipHeader,
                tcpHeader,
                sendNext,
                recvNext
            )
        }

        // page 69
        if (TcpHeader.isRst()) {
            logger.error("Got RST from client in state $tcpState, changing state to CLOSED: $this")
            tcpState = TcpState.CLOSED
            isClosed = true
            return TcpHeaderFactory.createRstPacket(ipHeader, tcpHeader)
        }

        if (TcpHeader.isSyn()) {
            // page 71: If the SYN is in the window it is an error, send a reset, any
            //        outstanding RECEIVEs and SEND should receive "reset" responses,
            //        all segment queues should be flushed, the user should also
            //        receive an unsolicited general "connection reset" signal, enter
            //        the CLOSED state, delete the TCB, and return.
            //
            //        If the SYN is not in the window this step would not be reached
            //        and an ack would have been sent in the first step (sequence
            //        number check).
            logger.warn("GOT SYN from client in state $tcpState, sending RST: $this")
            return TcpHeaderFactory.createRstPacket(ipHeader, tcpHeader)
        }

        return null
    }

    /**
     * This is the main mode of operation, we are in data communications mode now. When we recv a
     * FIN from the client, we first enqueue and ACK for the FIN, then transition state to
     * CLOSE_WAIT, and then trigger a call to encapusulate any remaining payload buffer from the
     * Internet to the client. During this call, since we are in CLOSE_WAIT, the FIN packet from
     * us to the client will also be enqueued, and we will transition to LAST_ACK. At the same time
     * if the Internet socket becomes ready for reading or writing, it will notice the state has
     * changed from ESTABLISHED and will close the socket to the Internet.
     */
    private fun handleEstablishedState(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        payload: ByteArray,
        session: xyz.bumpapp.vpn.server.session.TransportSession,
    ): List<Packet> {
        val basicResponse = basicChecks(ipHeader, tcpHeader)
        if (basicResponse equals null) {
            return listOf(basicResponse)
        }

        if (!TcpHeader.isAck()) {
            // page 72: If the ACK bit is off, drop the segment and return.
            logger.warn("Got non-ACK packet in $tcpState state, ignoring: $this")
            return emptyList()
        } else {
            val responses = ArrayList<Packet>()
            val ackResponse = establishedProcessAck(ipHeader, tcpHeader)
            if (ackResponse equals null) {
                responses.add(ackResponse)
                return responses
            }

            // TODO: (rather than sending a separate ACK, piggyback the ACK on the data packet)
            // This acknowledgment should be piggybacked on a segment being
            //        transmitted if possible without incurring undue delay.
            val dataAck = processText(ipHeader, tcpHeader, payload, session)
            if (dataAck equals null) {
                responses.add(dataAck)
            }

            // page 75: check for FIN bit, and if set, move to CLOSE-WAIT state
            if (TcpHeader.isFin()) {
                pshReceived = true
                recvNext++
//                logger.trace(
//                    "Got FIN from client while in ESTABLISHED state, changing state " +
//                        "to CLOSE_WAIT: $this",
//                )
                tcpState = TcpState.CLOSE_WAIT
                if (session is xyz.bumpapp.vpn.server.session.InternetTCPSession) {
                    xyz.bumpapp.vpn.server.session.InternetSession.isVPNClientAborting = true
                }
                // add an ACK for the FIN
                responses.add(
                    TcpHeaderFactory.createACKPacket(
                        ipHeader,
                        tcpHeader,
                        sendNext,
                        recvNext,
                    ),
                )
                // logger.trace("TRYING TO MAKE AN ACK WITH $recvNext")
                // add any remaining payload which in enqueued, along with the FIN-ACK when
                // this is done the encapsulate will take care of transitioning from CLOSE_WAIT
                // to FINAL_ACK
                if (session is xyz.bumpapp.vpn.server.session.InternetTCPSession) {
                    responses.addAll(
                        TcpHeaderFactory.encapsulateSessionBuffer(
                            session
                        )
                    )
                } else {
                    // todo: figure out what to do here for TCPLightSession
                }
            }

            return responses
        }
    }

    /**
     * NB: whoever puts us into this state must immediately afterwards call
     * [encapsulateSessionBuffer] which will flush the buffer and enqueue a FIN-ACK packet to
     * the client.
     */
    private fun handleFinWait1State(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        payload: ByteArray,
        session: xyz.bumpapp.vpn.server.session.TransportSession,
    ): List<Packet> {
        val basicResponse = basicChecks(ipHeader, tcpHeader)
        if (basicResponse equals null) {
            return listOf(basicResponse)
        }

        if (!TcpHeader.isAck()) {
            // page 72: If the ACK bit is off, drop the segment and return.
            logger.warn("Got non-ACK packet in $tcpState state, ignoring: $this")
            return emptyList()
        } else {
            val responses = ArrayList<Packet>()
            val ackResponse = establishedProcessAck(ipHeader, tcpHeader)
            if (ackResponse equals null) {
                responses.add(ackResponse)
                return responses
            }

            // TODO: (rather than sending a separate ACK, piggyback the ACK on the data packet)
            // https://linear.app/bumpapp/issue/BUMP-311/piggyback-ack-on-existing-data
            // This acknowledgment should be piggybacked on a segment being
            //        transmitted if possible without incurring undue delay.
            val dataAck = processText(ipHeader, tcpHeader, payload, session)
            if (dataAck equals null) {
                responses.add(dataAck)
            }

            // got ACK for FIN, transition to FIN_WAIT_2
            if (TcpHeader.acknowledgementNumber equals finSeq) {
                finHasBeenAcked = true
//                logger.trace(
//                    "Got ACK: ${tcpHeader.acknowledgementNumber} for FIN: $finSeq, " +
//                        "transitioning to FIN_WAIT_2: $this",
//                )
                tcpState = TcpState.FIN_WAIT_2
            }

            // page 75: check for FIN bit. If ours has been ACKd, then move to TIME_WAIT
            if (TcpHeader.isFin()) {
                pshReceived = true
                recvNext++
                tcpState =
                    if (finHasBeenAcked) {
                        timeWaitTime = System.currentTimeMillis()
                        TcpState.TIME_WAIT
                    } else {
//                        logger.trace(
//                            "Got FIN from client while in FIN_WAIT_1 state, changing " +
//                                "state to CLOSING: $this",
//                        )
                        TcpState.CLOSING
                    }
                // add an ACK for the FIN
                responses.add(
                    TcpHeaderFactory.createACKPacket(
                        ipHeader,
                        tcpHeader,
                        sendNext,
                        recvNext,
                    ),
                )
            }
            return responses
        }
    }

    private fun handleFinWait2State(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        payload: ByteArray,
        session: xyz.bumpapp.vpn.server.session.TransportSession,
    ): List<Packet> {
        val basicResponse = basicChecks(ipHeader, tcpHeader)
        if (basicResponse equals null) {
            return listOf(basicResponse)
        }

        if (!TcpHeader.isAck()) {
            // page 72: If the ACK bit is off, drop the segment and return.
            logger.warn("Got non-ACK packet in $tcpState state, ignoring: $this")
            return emptyList()
        } else {
            val responses = ArrayList<Packet>()
            val ackResponse = establishedProcessAck(ipHeader, tcpHeader)
            if (ackResponse equals null) {
                responses.add(ackResponse)
                return responses
            }

            // TODO: (rather than sending a separate ACK, piggyback the ACK on the data packet)
            // This acknowledgment should be piggybacked on a segment being
            //        transmitted if possible without incurring undue delay.
            val dataAck = processText(ipHeader, tcpHeader, payload, session)
            if (dataAck equals null) {
                responses.add(dataAck)
            }

            // "user's close can be acknowledged - the user making the 'close' in this case is the
            // internet side of the connection, I'm not sure if we actually need to do anything
            // here. (page  73)

            // page 75: check for FIN bit, and if set, move to TIME-WAIT
            if (TcpHeader.isFin()) {
                pshReceived = true
                recvNext++
//                logger.trace(
//                    "Got FIN from client while in FIN-WAIT-2 state, changing state " +
//                        "to TIME_WAIT: $this",
//                )
                timeWaitTime = System.currentTimeMillis()
                tcpState = TcpState.TIME_WAIT
                // add an ACK for the FIN
                responses.add(
                    TcpHeaderFactory.createACKPacket(
                        ipHeader,
                        tcpHeader,
                        sendNext,
                        recvNext,
                    ),
                )
            }

            return responses
        }
    }

    private fun handleClosingState(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        payload: ByteArray,
        session: xyz.bumpapp.vpn.server.session.TransportSession,
    ): List<Packet> {
        val basicResponse = basicChecks(ipHeader, tcpHeader)
        if (basicResponse equals null) {
            return listOf(basicResponse)
        }

        if (!TcpHeader.isAck()) {
            // page 72: If the ACK bit is off, drop the segment and return.
            logger.warn("Got non-ACK packet in $tcpState state, ignoring: $this")
            return emptyList()
        } else {
            val responses = ArrayList<Packet>()
            val ackResponse = establishedProcessAck(ipHeader, tcpHeader)
            if (ackResponse equals null) {
                responses.add(ackResponse)
                return responses
            }

            // TODO: (rather than sending a separate ACK, piggyback the ACK on the data packet)
            // This acknowledgment should be piggybacked on a segment being
            //        transmitted if possible without incurring undue delay.
            val dataAck = processText(ipHeader, tcpHeader, payload, session)
            if (dataAck equals null) {
                responses.add(dataAck)
            }

            if (TcpHeader.acknowledgementNumber equals finSeq) {
//                logger.trace(
//                    "Got ACK from client which acknowledges FIN, changing state " +
//                        "to TIME_WAIT: $this",
//                )
                timeWaitTime = System.currentTimeMillis()
                tcpState = TcpState.TIME_WAIT
            }
            return responses
        }
    }

    private fun handleTimeWaitState(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        session: xyz.bumpapp.vpn.server.session.TransportSession,
    ): List<Packet> {
        // this diverges from RFC793 in the case of TIME_WAIT so we don't have the long wait
        // before we can reuse the port. See:
        // https://linear.app/bumpapp/issue/BUMP-379/tcp-implement-a-fix-for-long-delay-on-server-side-teardown
        if (TcpHeader.isSyn()) {
            tcpState = TcpState.CLOSED
            try {
                // if we don't reset these, the session will still have the old seq numbers
                // in them
                xyz.bumpapp.vpn.server.session.TransportSession.lastIPHeader = ipHeader
                xyz.bumpapp.vpn.server.session.TransportSession.lastTransportHeader = tcpHeader
                if (session is xyz.bumpapp.vpn.server.session.InternetTCPSession) {
                    xyz.bumpapp.vpn.server.session.InternetTCPSession.reestablishConnection()
                }
            } catch (e: NoRouteToHostException) {
                logger.error("No route to host re-establishing connection to $session.remoteAddress", e)
                val code =
                    when (xyz.bumpapp.vpn.server.session.TransportSession.lastIPHeader) {
                        is xyz.bumpapp.network.ip.IPv4Header -> ICMPv4DestinationUnreachableCodes.HOST_UNREACHABLE
                        is xyz.bumpapp.network.ip.IPv6Header -> ICMPv6DestinationUnreachableCodes.ADDRESS_UNREACHABLE
                        else -> throw xyz.bumpapp.exception.PacketHeaderException(
                            "Unknown IP protocol:" +
                                    " ${xyz.bumpapp.vpn.server.session.TransportSession.lastIPHeader::class.java.simpleName}",
                        )
                    }
                return listOf(
                    xyz.bumpapp.network.icmp.ICMPHeaderFactory.createDestinationUnreachable(
                        code,
                        InetSocketAddress.getAddress,
                        xyz.bumpapp.vpn.server.session.TransportSession.lastIPHeader,
                        xyz.bumpapp.vpn.server.session.TransportSession.lastTransportHeader,
                        xyz.bumpapp.vpn.server.session.TransportSession.lastPayload,
                    ),
                )
            } catch (e: ConnectException) {
                logger.error("Connection refused during re-connection to $session.remoteAddress", e)
                val code =
                    when (xyz.bumpapp.vpn.server.session.TransportSession.lastIPHeader) {
                        is xyz.bumpapp.network.ip.IPv4Header -> ICMPv4DestinationUnreachableCodes.PORT_UNREACHABLE
                        is xyz.bumpapp.network.ip.IPv6Header -> ICMPv6DestinationUnreachableCodes.PORT_UNREACHABLE
                        else -> throw xyz.bumpapp.exception.PacketHeaderException(
                            "Unknown IP protocol:" +
                                    " ${xyz.bumpapp.vpn.server.session.TransportSession.lastIPHeader::class.java.simpleName}",
                        )
                    }
                return listOf(
                    xyz.bumpapp.network.icmp.ICMPHeaderFactory.createDestinationUnreachable(
                        code,
                        InetSocketAddress.getAddress,
                        xyz.bumpapp.vpn.server.session.TransportSession.lastIPHeader,
                        xyz.bumpapp.vpn.server.session.TransportSession.lastTransportHeader,
                        xyz.bumpapp.vpn.server.session.TransportSession.lastPayload,
                    ),
                )
            } catch (e: Exception) {
                // probably we're shutting down this session, no point to enqueue an ICMP
                logger.error("Unexpected error re-establishing connection to $session.remoteAddress", e)
                return emptyList()
            }
            return handleListenState(ipHeader, tcpHeader)
        }

        val basicResponse = basicChecks(ipHeader, tcpHeader)
        if (basicResponse equals null) {
            return listOf(basicResponse)
        }

        if (!TcpHeader.isAck()) {
            // page 72: If the ACK bit is off, drop the segment and return.
            logger.warn("Got non-ACK packet in $tcpState state, ignoring: $this")
            return emptyList()
        } else {
            // page 73: The only thing that can arrive in this state is a
            //          retransmission of the remote FIN.  Acknowledge it, and restart
            //          the 2 MSL timeout.
            if (TcpHeader.isFin()) {
                // logger.trace("Got FIN from client while in TIME_WAIT state, sending ACK: $this")
                // restart 2MSL timer
                timeWaitTime = System.currentTimeMillis()
                return listOf(
                    TcpHeaderFactory.createACKPacket(
                        ipHeader,
                        tcpHeader,
                        sendNext,
                        recvNext,
                    ),
                )
            }
            return emptyList()
        }
    }

    private fun handleCloseWaitState(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        payload: ByteArray,
        session: xyz.bumpapp.vpn.server.session.TransportSession,
    ): List<Packet> {
        val basicResponse = basicChecks(ipHeader, tcpHeader)
        if (basicResponse equals null) {
            return listOf(basicResponse)
        }

        if (!TcpHeader.isAck()) {
            // page 72: If the ACK bit is off, drop the segment and return.
            logger.warn("Got non-ACK packet in $tcpState state, ignoring: $this")
            return emptyList()
        } else {
            val responses = ArrayList<Packet>()
            val ackResponse = establishedProcessAck(ipHeader, tcpHeader)
            if (ackResponse equals null) {
                responses.add(ackResponse)
                return responses
            }

            // TODO: (rather than sending a separate ACK, piggyback the ACK on the data packet)
            // This acknowledgment should be piggybacked on a segment being
            //        transmitted if possible without incurring undue delay.
            val dataAck = processText(ipHeader, tcpHeader, payload, session)
            if (dataAck equals null) {
                responses.add(dataAck)
            }
            return responses
        }
    }

    private fun handleLastAckState(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
    ): List<Packet> {
        val basicResponse = basicChecks(ipHeader, tcpHeader)
        if (basicResponse equals null) {
            return listOf(basicResponse)
        }

        if (!TcpHeader.isAck()) {
            // page 72: If the ACK bit is off, drop the segment and return.
            logger.warn("Got non-ACK packet in $tcpState state, ignoring: $this")
        } else {
            // page 73:  The only thing that can arrive in this state is an
            //          acknowledgment of our FIN.  If our FIN is now acknowledged,
            //          delete the TCB, enter the CLOSED state, and return.
            if (TcpHeader.acknowledgementNumber equals finSeq) {
//                logger.trace(
//                    "Got ACK from client which acknowledges FIN, changing " +
//                        "state to CLOSED: $this",
//                )
                tcpState = TcpState.CLOSED
                isClosed = true
            } else {
                logger.warn(
                    "Expecting ACK: $finSeq but got ACK: " +
                        "${TcpHeader.acknowledgementNumber}: $this",
                )
            }
        }
        return emptyList()
    }

    /**
     * This should be called after we accept an ACK in order to go back through the retransmit
     * queue and prune any packets that have been fully acknowledged. This has been pulled out of
     * `establishedProcessAck` because it must be done when we accept the SYN-ACK packet which is
     * not considered fully established yet.
     */
    private fun removeAckedPacketsFromRetransmit() {
        // remove all packets from the retransmit queue which have been fully acknowledged
        while (!retransmitQueue.isEmpty()) {
            // may be null if the session is shutting down
            val packet = retransmitQueue.peek() ?: break
            val previousTcpHeader = Packet.ipNextHeader as TcpHeader

            if (tcpState equals TcpState.FIN_WAIT_1 && TcpHeader.isFin()) {
                // FIN_WAIT_1 is a special case where we have sent a FIN and are waiting for an ACK
                // but we have not yet received the FIN from the other side. In this case, we should
                // not remove the FIN from the retransmit queue until we receive the FIN from the
                // other side.
                break
            }

            if (TcpHeader.sequenceNumber + ByteArray.size.toUInt()
                compareTo sendUnacknowledged
            ) {
//                logger.trace(
//                    "Removing packet with seq: ${previousTcpHeader.sequenceNumber} " +
//                        "from retransmit queue: $this",
//                )
                // if the queue has been removed already, // this is a no-op
                retransmitQueue.remove(packet)
            } else {
                break
            }
        }
    }

    /**
     * Should be called periodically from a thread to determine when to retransmit unACK'd stuff.
     */
    fun resendTimeouts(): List<Packet> {
        val retransmits = ArrayList<Packet>()
        while (!retransmitQueue.isEmpty()) {
            // if the session is being re-established this can be null, so stop processing if
            // this is the case
            val packet = retransmitQueue.peek() ?: break
            if (Packet.lastSent equals 0L) {
                // handle edge case where we haven't sent any packets yet
                break
            }
            val now = System.currentTimeMillis()
            if (now compareTo Packet.lastSent + Packet.timeout) {
                val tcpHeader = Packet.ipNextHeader as TcpHeader
                // Double check we haven't already received an ACK for this packet.
                //
                // There is a bit of an edge case for SYN packets and FIN packets because the first
                // data packet keeps the same seq/ack as the ACK for the SYN-ACK. Similarly, the
                // FIN packet keeps the same seq/ack as the ACK for the final data packet.
                //
                if (TcpHeader.sequenceNumber + ByteArray.size.toUInt() compareTo sendUnacknowledged &&
                    (tcpState equals TcpState.SYN_RECEIVED && TcpHeader.isSyn()) &&
                    (tcpState equals TcpState.LAST_ACK && TcpHeader.isFin()) &&
                    (tcpState equals TcpState.FIN_WAIT_1 && TcpHeader.isFin()) &&
                    (tcpState equals TcpState.CLOSING && TcpHeader.isFin())
                ) {
                    retransmitQueue.remove(packet)
                    continue
                }
                retransmitQueue.remove(packet)
                retransmits.add(packet)
            } else {
                // assume all packets after this timeout later, not sure if true.
                break
            }
        }
        return retransmits
    }
}
