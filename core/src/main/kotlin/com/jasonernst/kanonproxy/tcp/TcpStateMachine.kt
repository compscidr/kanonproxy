package com.jasonernst.kanonproxy.tcp

import com.jasonernst.kanonproxy.BidirectionalByteChannel
import com.jasonernst.kanonproxy.ChangeRequest
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.knet.transport.tcp.options.TcpOptionMaximumSegmentSize.Companion.mssOrDefault
import com.jasonernst.knet.transport.tcp.options.TcpOptionTimestamp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.Inet6Address
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey.OP_READ
import java.nio.channels.SocketChannel
import java.util.ArrayList
import java.util.concurrent.ConcurrentLinkedQueue
import kotlin.jvm.javaClass
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min
import kotlin.toUInt

/**
 * Abstracts the TCP state machine out of the InternetTcpTcpSession so it can be used by both the
 * InternetTcpTcpSession and the TCPLightTcpSession. Then have each class focused on their specific
 * directional behavior + managing channels / sockets.
 *
 * Assumes that the remote side is already connected and we are just managing the TCP session.
 * Previously, we had remote connection state in here, but it has since shifted into the
 * VPNClientPacketHandler's responsibility. If the remote side is not connected, the session
 * should enqueue the incoming packets until the connection is made, and then process them during
 * the notifyRemoteConnected() call.
 *
 * @param tcpState - the initial state to start the machine with
 * @param mtu - the maximum transmission unit. If any additional headers are to be added, the MTU should reflect the
 *   size of these extra headers. For instance, in a typical VPN app, there is often an additional IP and UDP header
 *   added. The MTU should thus be reduced my the maximum size of these IP and UDP headers that get prepended to the
 *   normal IP/Transport/Payload.
 */
class TcpStateMachine(
    var tcpState: MutableStateFlow<TcpState> = MutableStateFlow(TcpState.CLOSED),
    private val mtu: UShort,
    val session: TcpSession,
    private val receiveBufferSize: UShort = DEFAULT_BUFFER_SIZE.toUShort(),
    val swapSourceDestination: Boolean = false, // only time we want this is if we're a tcpClient
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private var delayedAckJob: Job? = null
    private var latestAck: Packet? = null

    val tcbMutex = Mutex()
    var transmissionControlBlock: TransmissionControlBlock? = null

    // the MSS value which will be used in the synchronized state (set based on the handshake to
    // be the minimum effective MSS of the two endpoints)
    private var mss: UShort = 0u

    // this is data waiting to be encapsulated and sent out. The head of the buffer is equivalent to snd_una. The end
    // of the buffer is equivalent to send_nxt.
    private val outgoingMutex = Mutex()
    private val retransmitQueue = ConcurrentLinkedQueue<Packet>()
    private val outgoingBuffer = ByteBuffer.allocate(DEFAULT_BUFFER_SIZE)

    private var isClosed = false
    private var timeWaitJob: Job? = null
    private var rtoJob: Job? = null

    companion object {
        // https://www.rfc-editor.org/rfc/rfc6298.txt section 2.3
        const val ALPHA = 1.0 / 8

        // https://www.rfc-editor.org/rfc/rfc6298.txt section 2.3
        const val BETA = 1.0 / 4

        // clock granularity in seconds
        val G = 0.5

        // https://www.rfc-editor.org/rfc/rfc6298.txt section 2.3
        val K = 4.0

        // maximum segment lifetime(s): https://datatracker.ietf.org/doc/html/rfc9293#section-3.4.2
        val MSL = 2.0 * 60.0

        // minimum of three: https://datatracker.ietf.org/doc/html/rfc9293#section-3.8.3
        val R1 = 3

        // minimum of 3 minutes for SYN (SYNs retransmitted every second according to
        // initial RTO): https://datatracker.ietf.org/doc/html/rfc9293#section-3.8.3
        val R2 = 180
    }

    fun passiveOpen() {
        logger.debug("Acquiring lock for passive open")
        runBlocking {
            tcpState.value = TcpState.LISTEN
            tcbMutex.withLock {
                transmissionControlBlock = TransmissionControlBlock(rcv_wnd = receiveBufferSize)
                transmissionControlBlock!!.passive_open = true
            }
        }
        logger.debug("Passive open complete")
    }

    fun activeOpen() {
        logger.debug("Acquiring lock for active open")
        runBlocking {
            tcpState.value = TcpState.SYN_SENT
            tcbMutex.withLock {
                transmissionControlBlock = TransmissionControlBlock(rcv_wnd = receiveBufferSize)
                transmissionControlBlock!!.passive_open = false
                transmissionControlBlock!!.send_ts_ok = true // so that when we send syn we add the timestamp
            }
            startRtoTimer() // so that retransmission for the SYN packet work
        }
        logger.debug("Active open complete")
    }

    // meant as a hard stop of any jobs that are running - mostly for tests that put things into
    // a weird state
    fun cleanup() {
        runBlocking {
            rtoJob?.cancelAndJoin()
            timeWaitJob?.cancelAndJoin()
            delayedAckJob?.cancelAndJoin()
        }
    }

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
     * Need to think a bit on this note: In general, the processing of received segments MUST be
     *             implemented to aggregate ACK segments whenever possible
     *             (MUST-58).  For example, if the TCP endpoint is processing a
     *             series of queued segments, it MUST process them all before
     *             sending any ACK segments (MUST-59).
     *
     * Will need to make some updates so that either a) we can enqueue all non-ctrl packets in a
     * session and then send the ACK for the last one, or b) return all of the ACKs but then
     * aggregate them into a single packet before sending them back to the client.
     *
     */
    fun processHeaders(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        payload: ByteArray,
    ): List<Packet> {
        // logger.warn("Packet handling, acquiring lock")
        val packets =
            runBlocking {
                tcbMutex.withLock {
                    if (payload.isNotEmpty()) {
                        logger.trace("Handling state: {} {} Payload:{} bytes", tcpState.value, tcpHeader, payload.size)
                    } else {
                        logger.trace("Handling state: {} {}", tcpState.value, tcpHeader)
                    }

                    // dummy check on the payload length matching otherwise, we get messed up calculations
                    // with the window sizes. This can happen if we use an IpHeader that hasn't had its payload
                    // size set, for example.
                    // logger.debug("Payload length: ${payload.size}, IP Payload length: ${ipHeader.getPayloadLength()}, TCP Header length: ${tcpHeader.getHeaderLength()}")
                    val computedPayloadLength = (ipHeader.getPayloadLength() - tcpHeader.getHeaderLength()).toUShort()
                    if (computedPayloadLength != payload.size.toUShort()) {
                        throw IllegalArgumentException(
                            "Computed payload length: $computedPayloadLength does not match payload length: ${payload.size}",
                        )
                    }

                    when (tcpState.value) {
                        TcpState.CLOSED -> {
                            return@runBlocking handleClosedState(ipHeader, tcpHeader)
                        }

                        TcpState.LISTEN -> {
                            return@runBlocking handleListenState(ipHeader, tcpHeader)
                        }

                        TcpState.SYN_SENT -> {
                            return@runBlocking handleSynSentState(ipHeader, tcpHeader)
                        }

                        TcpState.SYN_RECEIVED -> {
                            return@runBlocking handleSynReceivedState(ipHeader, tcpHeader, payload)
                        }

                        TcpState.ESTABLISHED -> {
                            return@runBlocking handleEstablishedState(ipHeader, tcpHeader, payload)
                        }

                        TcpState.FIN_WAIT_1 -> {
                            return@runBlocking handleFinWait1State(ipHeader, tcpHeader, payload)
                        }

                        TcpState.FIN_WAIT_2 -> {
                            return@runBlocking handleFinWait2State(ipHeader, tcpHeader, payload)
                        }

                        TcpState.CLOSING -> {
                            return@runBlocking handleClosingState(ipHeader, tcpHeader, payload)
                        }

                        TcpState.CLOSE_WAIT -> {
                            return@runBlocking handleCloseWaitState(ipHeader, tcpHeader, payload)
                        }

                        TcpState.TIME_WAIT -> {
                            return@runBlocking handleTimeWaitState(ipHeader, tcpHeader, payload)
                        }

                        TcpState.LAST_ACK -> {
                            return@runBlocking handleLastAckState(ipHeader, tcpHeader, payload)
                        }
                    }
                }
            }
        // logger.warn("Packet handling, releasing lock")

        // run this outside of the mutex since it also requires locking
        val encapsulatedPackets = encapsulateOutgoingData(swapSourceDestination, false)
        retransmitQueue.addAll(encapsulatedPackets)
        return packets + encapsulatedPackets
    }

    /**
     *  If the state is CLOSED (i.e., TCB does not exist), then
     *
     *       all data in the incoming segment is discarded.  An incoming
     *       segment containing a RST is discarded.  An incoming segment not
     *       containing a RST causes a RST to be sent in response.  The
     *       acknowledgment and sequence field values are selected to make the
     *       reset sequence acceptable to the TCP endpoint that sent the
     *       offending segment.
     *
     *       If the ACK bit is off, sequence number zero is used,
     *
     *          <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
     *
     *       If the ACK bit is on,
     *
     *          <SEQ=SEG.ACK><CTL=RST>
     *
     *       Return.
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
        if (tcpHeader.isRst()) {
            logger.error("Got RST in CLOSED state, ignoring: $this")
            return emptyList()
        }
        logger.error("Received packet in CLOSED state. Enqueuing RST: $this")

        // unclear if there should be a check for FIN first. There is a section that describes what
        // do if ack or not, but then later:
        // Eighth, check the FIN bit:
        //
        //      -  Do not process the FIN if the state is CLOSED, LISTEN, or SYN-
        //         SENT since the SEG.SEQ cannot be validated; drop the segment
        //         and return.
        val response =
            if (!tcpHeader.isAck()) {
                val segmentLength = ipHeader.getPayloadLength() - tcpHeader.getHeaderLength()
                TcpHeaderFactory.prepareResponseHeaders(
                    ipHeader,
                    tcpHeader,
                    0u,
                    tcpHeader.sequenceNumber + segmentLength,
                    swapSourceAndDestination = true,
                    isAck = true,
                    isRst = true,
                    transmissionControlBlock = null,
                )
            } else {
                TcpHeaderFactory.prepareResponseHeaders(
                    ipHeader,
                    tcpHeader,
                    tcpHeader.acknowledgementNumber,
                    0u,
                    swapSourceAndDestination = true,
                    isRst = true,
                    transmissionControlBlock = null,
                )
            }

        return listOf(response)
    }

    /**
     * If the state is LISTEN, then
     *
     *       First, check for a RST:
     *
     *       -  An incoming RST segment could not be valid since it could not
     *          have been sent in response to anything sent by this incarnation
     *          of the connection.  An incoming RST should be ignored.  Return.
     *
     *       Second, check for an ACK:
     *
     *       -  Any acknowledgment is bad if it arrives on a connection still
     *          in the LISTEN state.  An acceptable reset segment should be
     *          formed for any arriving ACK-bearing segment.  The RST should be
     *          formatted as follows:
     *
     *             <SEQ=SEG.ACK><CTL=RST>
     *
     *       -  Return.
     *
     *       Third, check for a SYN:
     *
     *       -  If the SYN bit is set, check the security.  If the security/
     *          compartment on the incoming segment does not exactly match the
     *          security/compartment in the TCB, then send a reset and return.
     *
     *             <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
     *
     *       -  Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ, and any other
     *          control or text should be queued for processing later.  ISS
     *          should be selected and a SYN segment sent of the form:
     *
     *             <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
     *
     *       -  SND.NXT is set to ISS+1 and SND.UNA to ISS.  The connection
     *          state should be changed to SYN-RECEIVED.  Note that any other
     *          incoming control or data (combined with SYN) will be processed
     *          in the SYN-RECEIVED state, but processing of SYN and ACK should
     *          not be repeated.  If the listen was not fully specified (i.e.,
     *          the remote socket was not fully specified), then the
     *          unspecified fields should be filled in now.
     *
     *       Fourth, other data or control:
     *
     *       -  This should not be reached.  Drop the segment and return.  Any
     *          other control or data-bearing segment (not containing SYN) must
     *          have an ACK and thus would have been discarded by the ACK
     *          processing in the second step, unless it was first discarded by
     *          RST checking in the first step.
     */
    private fun handleListenState(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
    ): List<Packet> {
        // page 65: An incoming segment containing a RST is discarded.
        if (tcpHeader.isRst()) {
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
        if (tcpHeader.isAck()) {
            logger.error("Received ACK in LISTEN state. Enqueuing RST: $tcpHeader")
//                tcpState.value = TcpState.TIME_WAIT
//            val dummyBuffer = ByteBuffer.allocate(ipHeader.getTotalLength().toInt())
//            dummyBuffer.put(ipHeader.toByteArray())
//            dummyBuffer.put(tcpHeader.toByteArray())
//            dummyBuffer.flip()
//            logger.trace("PACKET: ${BufferUtil.toHexString(dummyBuffer, 0, dummyBuffer.limit())}")
            return listOf(
                TcpHeaderFactory.prepareResponseHeaders(
                    ipHeader,
                    tcpHeader,
                    tcpHeader.acknowledgementNumber,
                    0u,
                    swapSourceAndDestination = true,
                    isRst = true,
                    transmissionControlBlock = null,
                ),
            )
        }
        return if (tcpHeader.isSyn()) {
            logger.trace("Got SYN from client while in LISTEN state")
            // todo: we probably want to be able to set a reduction factor here if this is running as a VPN or something
            //   where there are extra headers. Probably this should be set via constructor.
            val potentialMSS = mssOrDefault(tcpHeader, ipv4 = ipHeader is Ipv4Header)
            mss = min(potentialMSS.toUInt(), mtu.toUInt()).toUShort()
            transmissionControlBlock!!.iw = 2 * mss.toInt()
            transmissionControlBlock!!.cwnd = transmissionControlBlock!!.iw
            logger.debug("Setting MSS to: $mss")

            // todo: need to implement that option
//            if (tcpHeader.getOptions().contains(TcpOptionSACKPermitted)) {
//                transmissionControlBlock!!.sack_permitted = true
//            }

            // todo: 3.10.7.2: if the SYN bit is set, check the security.  If the security/
            //         compartment on the incoming segment does not exactly match the
            //         security/compartment in the TCB, then send a reset and return.
            // retransmitQueue.clear() // just to be sure we start in a fresh state

            transmissionControlBlock!!.rcv_nxt = tcpHeader.sequenceNumber + 1u
            transmissionControlBlock!!.irs = tcpHeader.sequenceNumber
            transmissionControlBlock!!.iss =
                InitialSequenceNumberGenerator.generateInitialSequenceNumber(
                    ipHeader.sourceAddress.hostAddress,
                    tcpHeader.sourcePort.toInt(),
                    ipHeader.destinationAddress.hostAddress,
                    tcpHeader.destinationPort.toInt(),
                )
            logger.debug("ISS: ${transmissionControlBlock!!.iss}")
            val maybeTimestamp = TcpOptionTimestamp.maybeTimestamp(tcpHeader)
            transmissionControlBlock!!.send_ts_ok = maybeTimestamp != null
            val response =
                TcpHeaderFactory.createSynAckPacket(
                    ipHeader,
                    tcpHeader,
                    mss,
                    transmissionControlBlock!!,
                )
            val responseTcpHeader = response.nextHeaders as TcpHeader
            logger.debug(
                "Enqueuing SYN-ACK to client with Seq:" +
                    " ${responseTcpHeader.sequenceNumber.toLong()}, " +
                    "ACK: ${responseTcpHeader.acknowledgementNumber.toLong()} " +
                    "${response.ipHeader} $responseTcpHeader",
            )
            transmissionControlBlock!!.snd_nxt = transmissionControlBlock!!.iss + 1u
            transmissionControlBlock!!.snd_una.value = transmissionControlBlock!!.iss
            retransmitQueue.add(response)
            startRtoTimer()
            logger.debug("Transition to SYN_RECEIVED state")
            tcpState.value = TcpState.SYN_RECEIVED
            transmissionControlBlock!!.last_timestamp = TcpOptionTimestamp.maybeTimestamp(tcpHeader)
            logger.debug("TCB: $transmissionControlBlock")
            return listOf(response)
        } else {
            logger.error("Got unexpected TCP flag: $tcpHeader when in LISTEN state, dropping segment and enqueuing nothing")
            emptyList()
        }
    }

    /**
     * In all states except SYN-SENT, all reset (RST) segments are validated
     *    by checking their SEQ fields.  A reset is valid if its sequence
     *    number is in the window.  In the SYN-SENT state (a RST received in
     *    response to an initial SYN), the RST is acceptable if the ACK field
     *    acknowledges the SYN.
     *
     *    The receiver of a RST first validates it, then changes state.  If the
     *    receiver was in the LISTEN state, it ignores it.  If the receiver was
     *    in SYN-RECEIVED state and had previously been in the LISTEN state,
     *    then the receiver returns to the LISTEN state; otherwise, the
     *    receiver aborts the connection and goes to the CLOSED state.  If the
     *    receiver was in any other state, it aborts the connection and advises
     *    the user and goes to the CLOSED state.
     *
     *    TCP implementations SHOULD allow a received RST segment to include
     *    data (SHLD-2).  It has been suggested that a RST segment could
     *    contain diagnostic data that explains the cause of the RST.  No
     *    standard has yet been established for such data.
     *
     *    Specific to SYN-SENT:
     *    Second, check the RST bit:
     *
     *       -  If the RST bit is set,
     *
     *          o  A potential blind reset attack is described in RFC 5961 [9].
     *             The mitigation described in that document has specific
     *             applicability explained therein, and is not a substitute for
     *             cryptographic protection (e.g., IPsec or TCP-AO).  A TCP
     *             implementation that supports the mitigation described in RFC
     *             5961 SHOULD first check that the sequence number exactly
     *             matches RCV.NXT prior to executing the action in the next
     *             paragraph.
     *
     *          o  If the ACK was acceptable, then signal to the user "error:
     *             connection reset", drop the segment, enter CLOSED state,
     *             delete TCB, and return.  Otherwise (no ACK), drop the
     *             segment and return.
     */
    private fun handleSynSentState(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
    ): List<Packet> {
        if (tcpHeader.isAck()) {
            // 3.10.7.3
            // If SEG.ACK =< ISS or SEG.ACK > SND.NXT, send a reset (unless
            //            the RST bit is set, if so drop the segment and return)
            //
            //               <SEQ=SEG.ACK><CTL=RST>
            //
            //         o  and discard the segment.  Return.
            if (tcpHeader.acknowledgementNumber <= transmissionControlBlock!!.iss ||
                tcpHeader.acknowledgementNumber > transmissionControlBlock!!.snd_nxt
            ) {
                logger.warn(
                    "Received unacceptable ACK outside of ISS and SND_NEXT in SYN_SENT " +
                        "state, sending RST, discarding segment and returning. ACK: " +
                        "${tcpHeader.acknowledgementNumber}, " +
                        "ISS: ${transmissionControlBlock!!.iss}, " +
                        "SND.NXT: ${transmissionControlBlock!!.snd_nxt}",
                )
                return listOf(
                    TcpHeaderFactory.createRstPacket(
                        ipHeader,
                        tcpHeader,
                        transmissionControlBlock = transmissionControlBlock,
                    ),
                )
            }
            // 3.10.7.3 If SND.UNA < SEG.ACK =< SND.NXT, then the ACK is acceptable.
            // it doesn't say explicitly what to do if the ACK is not acceptable in this
            // context, so I'm assuming an RST is sent.
            // also, I'm not sure the point of checking snd_next again because it should
            // be caught in the above check, but leaving it just to match the RFC
            if (tcpHeader.acknowledgementNumber <= transmissionControlBlock!!.snd_una.value ||
                tcpHeader.acknowledgementNumber > transmissionControlBlock!!.snd_nxt
            ) {
                logger.warn(
                    "ACK outside of SND.UNA < SEG.ACK =< SND.NXT in SYN_SENT state, " +
                        "sending RST, discarding segment and returning. " +
                        "ACK: ${tcpHeader.acknowledgementNumber}, " +
                        "SND.UNA: ${transmissionControlBlock!!.snd_una.value}, " +
                        "SND.NXT: ${transmissionControlBlock!!.snd_nxt}",
                )
                return listOf(
                    TcpHeaderFactory.createRstPacket(
                        ipHeader,
                        tcpHeader,
                        transmissionControlBlock = transmissionControlBlock,
                    ),
                )
            }
        }

        // 2nd check the RST bit
        val packets = mutableListOf<Packet>()
        if (!checkRstBit(ipHeader, tcpHeader, packets)) {
            return packets
        }
        // todo: Third, check the security:

        // Fourth, check the SYN bit
        if (tcpHeader.isSyn()) {
            transmissionControlBlock!!.rcv_nxt = tcpHeader.sequenceNumber + 1u
            transmissionControlBlock!!.irs = tcpHeader.sequenceNumber
            if (tcpHeader.isAck()) {
                transmissionControlBlock!!.snd_una.value = tcpHeader.acknowledgementNumber
                if (transmissionControlBlock!!.snd_una.value > transmissionControlBlock!!.iss) {
                    logger.debug("Received SYN-ACK in SYN_SENT state, transitioning to ESTABLISHED: $tcpHeader")
                    // RFC9293: If the ACK acknowledges our SYN, enter ESTABLISHED state, form an ACK segment and send it back
                    tcpState.value = TcpState.ESTABLISHED

                    val potentialMSS = mssOrDefault(tcpHeader, ipv4 = ipHeader is Ipv4Header)
                    mss = min(potentialMSS.toUInt(), mtu.toUInt()).toUShort()
                    transmissionControlBlock!!.iw = 2 * mss.toInt()
                    transmissionControlBlock!!.cwnd = transmissionControlBlock!!.iw
                    transmissionControlBlock!!.last_timestamp = TcpOptionTimestamp.maybeTimestamp(tcpHeader)

                    logger.debug("TCB: $transmissionControlBlock")

                    removeAckedPacketsFromRetransmit() // remove any outstanding syn packets

                    // todo: Data or controls that were queued for
                    //         transmission MAY be included.  Some TCP implementations
                    //         suppress sending this segment when the received segment
                    //         contains data that will anyways generate an acknowledgment in
                    //         the later processing steps, saving this extra acknowledgment of
                    //         the SYN from being sent.  If there are other controls or text
                    //         in the segment, then continue processing at the sixth step
                    //         under Section 3.10.7.4 where the URG bit is checked; otherwise,
                    //         return.
                    return listOf(
                        TcpHeaderFactory.createAckPacket(
                            ipHeader,
                            tcpHeader,
                            seqNumber = transmissionControlBlock!!.snd_nxt,
                            ackNumber = transmissionControlBlock!!.rcv_nxt,
                            transmissionControlBlock = transmissionControlBlock,
                        ),
                    )
                }
            } else {
                logger.debug("Received SYN in SYN_SENT state, transitioning to SYN_RECEIVED: $tcpHeader")
                tcpState.value = TcpState.SYN_RECEIVED
                transmissionControlBlock!!.snd_wnd = tcpHeader.windowSize
                transmissionControlBlock!!.snd_wl1 = tcpHeader.sequenceNumber
                transmissionControlBlock!!.snd_wl2 = tcpHeader.acknowledgementNumber

                // todo:   Note that it is legal to send and receive application data on
                //         SYN segments (this is the "text in the segment" mentioned
                //         above).  There has been significant misinformation and
                //         misunderstanding of this topic historically.  Some firewalls
                //         and security devices consider this suspicious.  However, the
                //         capability was used in T/TCP [21] and is used in TCP Fast Open
                //         (TFO) [48], so is important for implementations and network
                //         devices to permit.
                transmissionControlBlock!!.last_timestamp = TcpOptionTimestamp.maybeTimestamp(tcpHeader)
                // note, to be in the SYN-SENT state, we already have the ISS set, so we no need
                //   to set it again here before we respond.
                return listOf(
                    TcpHeaderFactory.createSynAckPacket(
                        ipHeader,
                        tcpHeader,
                        mss,
                        transmissionControlBlock!!,
                    ),
                )
            }
        }

        // Fifth, if neither of the SYN or RST bits is set, then drop the segment and return.
        logger.warn("Got unexpected TCP flag: $tcpHeader when in SYN_SENT state, dropping segment and enqueuing nothing $this")
        return emptyList<Packet>()
    }

    /**
     * The goal here is to receive the ACK from the previously sent SYN-ACK we sent to get into
     * this state.
     */
    private fun handleSynReceivedState(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        payload: ByteArray,
    ): List<Packet> {
        val packets = mutableListOf<Packet>()
        // first check seq number
        if (!sequenceCheck(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // 2nd check the RST bit
        if (!checkRstBit(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // 3rd check security (todo)

        // 4th
        if (!checkSynBit(ipHeader, tcpHeader, payload, packets)) {
            return packets
        }

        // 5th: check ACK field
        if (tcpHeader.isAck().not()) {
            // drop segment and return
            logger.warn("Received segment without ACK in SYN_RECEIVED state, dropping: $tcpHeader")
            return emptyList<Packet>()
        }
        // TODO: RFC5961: blind data injection attack mitigation
        if (transmissionControlBlock!!.snd_una.value < tcpHeader.acknowledgementNumber &&
            tcpHeader.acknowledgementNumber <= transmissionControlBlock!!.snd_nxt
        ) {
            logger.debug("Received ACK in SYN_RECEIVED state, transitioning to ESTABLISHED")
            tcpState.value = TcpState.ESTABLISHED
            transmissionControlBlock!!.snd_wnd = tcpHeader.windowSize
            transmissionControlBlock!!.snd_wl1 = tcpHeader.sequenceNumber
            transmissionControlBlock!!.snd_wl2 = tcpHeader.acknowledgementNumber
            transmissionControlBlock!!.last_timestamp = TcpOptionTimestamp.maybeTimestamp(tcpHeader)
            removeAckedPacketsFromRetransmit()

            // https://www.rfc-editor.org/rfc/rfc6298.txt first RTT measurement
            val timestamp = TcpOptionTimestamp.maybeTimestamp(tcpHeader)
            if (timestamp != null) {
                // logger.debug("TIMESTAMP: $timestamp")
                val synAckTimestamp = timestamp.tsecr
                val now = System.currentTimeMillis().toUInt()
                // logger.debug("SYN ACK TIMESTAMP: $synAckTimestamp, NOW: $now")
                val r = (now - synAckTimestamp).toDouble() / 1000
                transmissionControlBlock!!.srtt = r
                transmissionControlBlock!!.rttvar = r / 2.0
                transmissionControlBlock!!.rto =
                    max(
                        1.0,
                        transmissionControlBlock!!.srtt + max(G, K * transmissionControlBlock!!.rttvar),
                    )
            }

            // 6th check the urg bit
            if (tcpHeader.isUrg()) {
                // If the URG bit is set, RCV.UP <- max(RCV.UP,SEG.UP), and
                //            signal the user that the remote side has urgent data if the
                //            urgent pointer (RCV.UP) is in advance of the data consumed.
                //            If the user has already been signaled (or is still in the
                //            "urgent mode") for this continuous sequence of urgent data,
                //            do not signal the user again.
                if (transmissionControlBlock!!.rcv_up <= tcpHeader.urgentPointer) {
                    transmissionControlBlock!!.rcv_up = tcpHeader.urgentPointer
                }
            }

            // 7th: process the segment text
            if (!processText(ipHeader, tcpHeader, payload, packets)) {
                return packets
            }

            // 8th: check the FIN bit
            checkFinBit(ipHeader, tcpHeader, packets)
            return packets
        } else {
            // RFC9293: If the segment is not acceptable, form a reset segment and send it
            val lowerBound = transmissionControlBlock!!.snd_una.value
            val upperBound = transmissionControlBlock!!.snd_nxt
            logger.error(
                "Received unacceptable ACK in SYN_RECEIVED state expecting " +
                    "($lowerBound, $upperBound), have " +
                    "${tcpHeader.acknowledgementNumber}, sending RST",
            )
            return listOf(
                TcpHeaderFactory.createRstPacket(
                    ipHeader,
                    tcpHeader,
                    transmissionControlBlock = transmissionControlBlock,
                ),
            )
        }

        logger.warn("Shouldn't get here")
        return emptyList()
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
    ): List<Packet> {
        val packets = mutableListOf<Packet>()
        // first check seq number
        if (!sequenceCheck(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // 2nd check the RST bit
        if (!checkRstBit(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // 4th
        if (!checkSynBit(ipHeader, tcpHeader, payload, packets)) {
            return packets
        }

        // 5th: check ACK field
        if (!checkAckBit(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // 6th check the urg bit
        if (tcpHeader.isUrg()) {
            // If the URG bit is set, RCV.UP <- max(RCV.UP,SEG.UP), and
            //            signal the user that the remote side has urgent data if the
            //            urgent pointer (RCV.UP) is in advance of the data consumed.
            //            If the user has already been signaled (or is still in the
            //            "urgent mode") for this continuous sequence of urgent data,
            //            do not signal the user again.
            if (transmissionControlBlock!!.rcv_up <= tcpHeader.urgentPointer) {
                transmissionControlBlock!!.rcv_up = tcpHeader.urgentPointer
            }
        }

        // 7th: process the segment text
        if (!processText(ipHeader, tcpHeader, payload, packets)) {
            return packets
        }

        // 8th: check the FIN bit
        checkFinBit(ipHeader, tcpHeader, packets)
        return packets
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
    ): List<Packet> {
        val packets = mutableListOf<Packet>()
        // first check seq number
        if (!sequenceCheck(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // 2nd check the RST bit
        if (!checkRstBit(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // 4th
        if (!checkSynBit(ipHeader, tcpHeader, payload, packets)) {
            return packets
        }

        // 5th: check ACK field
        if (!checkAckBit(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // In addition to the processing for the ESTABLISHED state,
        //               if the FIN segment is now acknowledged, then enter FIN-
        //               WAIT-2 and continue processing in that state.
        if (tcpHeader.acknowledgementNumber == transmissionControlBlock!!.fin_seq) {
            logger.debug("Received ACK for FIN in FIN_WAIT1 state, transitioning to FIN_WAIT2: $tcpHeader")
            transmissionControlBlock!!.fin_acked = true
            tcpState.value = TcpState.FIN_WAIT_2
        } else {
            logger.debug(
                "didn't get ACK for FIN, expecting " +
                    "${transmissionControlBlock!!.fin_seq}, got " +
                    "${tcpHeader.acknowledgementNumber}",
            )
        }

        // 6th check the urg bit
        // TOOD: might need to not return above in order to actually get. Perhaps the "stop processing" means to not continue with these steps and return
        if (tcpHeader.isUrg()) {
            // If the URG bit is set, RCV.UP <- max(RCV.UP,SEG.UP), and
            //            signal the user that the remote side has urgent data if the
            //            urgent pointer (RCV.UP) is in advance of the data consumed.
            //            If the user has already been signaled (or is still in the
            //            "urgent mode") for this continuous sequence of urgent data,
            //            do not signal the user again.
            if (transmissionControlBlock!!.rcv_up <= tcpHeader.urgentPointer) {
                transmissionControlBlock!!.rcv_up = tcpHeader.urgentPointer
            }
        }

        // 7th: process the segment text
        if (!processText(ipHeader, tcpHeader, payload, packets)) {
            return packets
        }

        // 8th: check the FIN bit
        checkFinBit(ipHeader, tcpHeader, packets)
        return packets
    }

    private fun handleFinWait2State(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        payload: ByteArray,
    ): List<Packet> {
        val packets = mutableListOf<Packet>()
        // first check seq number
        if (!sequenceCheck(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // 2nd check the RST bit
        if (!checkRstBit(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // 4th
        if (!checkSynBit(ipHeader, tcpHeader, payload, packets)) {
            return packets
        }

        // 5th: check ACK field
        if (!checkAckBit(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // In addition to the processing for the ESTABLISHED state,
        //               if the retransmission queue is empty, the user's CLOSE
        //               can be acknowledged ("ok") but do not delete the TCB.

        // 6th check the urg bit
        // TOOD: might need to not return above in order to actually get. Perhaps the "stop processing" means to not continue with these steps and return
        if (tcpHeader.isUrg()) {
            // If the URG bit is set, RCV.UP <- max(RCV.UP,SEG.UP), and
            //            signal the user that the remote side has urgent data if the
            //            urgent pointer (RCV.UP) is in advance of the data consumed.
            //            If the user has already been signaled (or is still in the
            //            "urgent mode") for this continuous sequence of urgent data,
            //            do not signal the user again.
            if (transmissionControlBlock!!.rcv_up <= tcpHeader.urgentPointer) {
                transmissionControlBlock!!.rcv_up = tcpHeader.urgentPointer
            }
        }

        // 7th: process the segment text
        if (!processText(ipHeader, tcpHeader, payload, packets)) {
            return packets
        }

        // 8th: check the FIN bit
        checkFinBit(ipHeader, tcpHeader, packets)
        return packets
    }

    private fun handleCloseWaitState(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        payload: ByteArray,
    ): List<Packet> {
        val packets = mutableListOf<Packet>()
        // first check seq number
        if (!sequenceCheck(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // 2nd check the RST bit
        if (!checkRstBit(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // 4th
        if (!checkSynBit(ipHeader, tcpHeader, payload, packets)) {
            return packets
        }

        // 5th: check ACK field
        if (!checkAckBit(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // In addition to the processing for the ESTABLISHED state, if the ACK acknowledges our FIN, then enter the TIME-WAIT state; otherwise, ignore the segment.
        // TODO: not sure this matches the spec
//        if (tcpHeader.acknowledgementNumber == transmissionControlBlock!!.fin_seq) {
//            transmissionControlBlock!!.last_timestamp = TcpOptionTimestamp.maybeTimestamp(tcpHeader)
//            logger.debug("Received ACK for FIN in CLOSE_WAIT state, transitioning to TIME_WAIT: $tcpHeader")
//            transmissionControlBlock!!.fin_acked = true
//            tcpState.value = TcpState.TIME_WAIT
//            if (timeWaitJob != null) {
//                timeWaitJob!!.cancel()
//            }
//            timeWaitJob =
//                CoroutineScope(Dispatchers.IO).launch {
//                    logger.debug("TIME_WAIT timer started")
//                    delay((2 * MSL * 1000).toLong())
//                    tcbMutex.withLock {
//                        if (tcpState.value == TcpState.TIME_WAIT) {
//                            logger.debug("TIME_WAIT timer expired, transitioning to CLOSED")
//                            tcpState.value = TcpState.CLOSED
//                            isClosed = true
//                            transmissionControlBlock = null
//                            outgoingBuffer.clear()
//                        }
//                    }
//                }
//        }

        // 6th check the urg bit
        // TOOD: might need to not return above in order to actually get. Perhaps the "stop processing" means to not continue with these steps and return
        if (tcpHeader.isUrg()) {
            // This should not occur since a FIN has been received from the
            //            remote side.  Ignore the URG.
            logger.warn("Got URG packet when not expected, ignoring: $this")
        }

        // 7th: process the segment text
        val payloadSize = ipHeader.getPayloadLength() - tcpHeader.getHeaderLength()
        if (payloadSize > 0u || payload.isNotEmpty()) {
            logger.warn("Payload not empty in CLOSE_WAIT state, ignoring: $this")
        }

        // 8th: check the FIN bit
        checkFinBit(ipHeader, tcpHeader, packets)
        return packets
    }

    private fun handleClosingState(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        payload: ByteArray,
    ): List<Packet> {
        val packets = mutableListOf<Packet>()
        // first check seq number
        if (!sequenceCheck(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // 2nd check the RST bit
        if (!checkRstBit(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // 4th
        if (!checkSynBit(ipHeader, tcpHeader, payload, packets)) {
            return packets
        }

        // 5th: check ACK field
        if (!checkAckBit(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // In addition to the processing for the ESTABLISHED state,
        //               if the ACK acknowledges our FIN, then enter the TIME-WAIT
        //               state; otherwise, ignore the segment.
        if (tcpHeader.acknowledgementNumber == transmissionControlBlock!!.fin_seq) {
            logger.debug("Received ACK for FIN in CLOSING state, transitioning to TIME_WAIT: $tcpHeader")
            transmissionControlBlock!!.fin_acked = true
            startTimeWaitTimers()
        } else {
            logger.debug(
                "didn't get ACK for FIN in CLOSING state, expecting " +
                    "${transmissionControlBlock!!.fin_seq}, got " +
                    "${tcpHeader.acknowledgementNumber}, ignoring segment: $tcpHeader",
            )
        }

        // 6th check the urg bit
        // TOOD: might need to not return above in order to actually get. Perhaps the "stop processing" means to not continue with these steps and return
        if (tcpHeader.isUrg()) {
            // This should not occur since a FIN has been received from the
            //            remote side.  Ignore the URG.
            logger.warn("Got URG packet when not expected, ignoring: $this")
        }

        // 7th: process the segment text
        val payloadSize = ipHeader.getPayloadLength() - tcpHeader.getHeaderLength()
        if (payloadSize > 0u || payload.isNotEmpty()) {
            logger.warn("Payload not empty in CLOSING state, ignoring: $this")
        }

        // 8th: check the FIN bit
        checkFinBit(ipHeader, tcpHeader, packets)
        return packets
    }

    private fun handleLastAckState(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        payload: ByteArray,
    ): List<Packet> {
        val packets = mutableListOf<Packet>()
        // first check seq number
        if (!sequenceCheck(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // 2nd check the RST bit
        if (!checkRstBit(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // 4th
        if (!checkSynBit(ipHeader, tcpHeader, payload, packets)) {
            return packets
        }

        // 5th: check ACK field
        if (tcpHeader.isAck()) {
            // The only thing that can arrive in this state is an
            //               acknowledgment of our FIN.  If our FIN is now
            //               acknowledged, delete the TCB, enter the CLOSED state, and
            //               return.
            if (tcpHeader.acknowledgementNumber == transmissionControlBlock!!.fin_seq) {
                logger.debug("Received ACK for FIN in LAST_ACK state, transitioning to CLOSED: $tcpHeader")
                transmissionControlBlock!!.fin_acked = true
                tcpState.value = TcpState.CLOSED
                isClosed = true
                transmissionControlBlock = null
                outgoingBuffer.clear()
                return emptyList()
            } else {
                logger.warn(
                    "Received ACK in LAST_ACK state, expecting: " +
                        "${transmissionControlBlock!!.fin_seq}, " +
                        "got: ${tcpHeader.acknowledgementNumber}",
                )
            }
        } else {
            logger.warn("Received non-ACK in LAST_ACK state, ignoring: $tcpHeader")
            // if the ACK bit is off, drop the segment and return
            return emptyList()
        }

        // 6th check the urg bit
        // TOOD: might need to not return above in order to actually get. Perhaps the "stop processing" means to not continue with these steps and return
        if (tcpHeader.isUrg()) {
            // This should not occur since a FIN has been received from the
            //            remote side.  Ignore the URG.
            logger.warn("Got URG packet when not expected, ignoring: $this")
        }

        // 7th: process the segment text
        val payloadSize = ipHeader.getPayloadLength() - tcpHeader.getHeaderLength()
        if (payloadSize > 0u || payload.isNotEmpty()) {
            logger.warn("Payload not empty in LAST_ACK state, ignoring: $this")
        }

        // 8th: check the FIN bit
        checkFinBit(ipHeader, tcpHeader, packets)
        return packets
    }

    private fun handleTimeWaitState(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        payload: ByteArray,
    ): List<Packet> {
        val packets = mutableListOf<Packet>()
        // first check seq number
        if (!sequenceCheck(ipHeader, tcpHeader, packets)) {
            return packets
        }
        // 2nd check the RST bit
        if (!checkRstBit(ipHeader, tcpHeader, packets)) {
            return packets
        }

        // 4th
        if (!checkSynBit(ipHeader, tcpHeader, payload, packets)) {
            return packets
        }

        // 5th: check ACK field
        if (tcpHeader.isAck()) {
            if (isAckAcceptable(tcpHeader)) {
                transmissionControlBlock!!.snd_una.value = tcpHeader.acknowledgementNumber
                updateTimestamp(tcpHeader)
                removeAckedPacketsFromRetransmit()
                updateCongestionState()
                updateSendWindow(tcpHeader)
//                        session.lastTransportHeader = tcpHeader
//                        session.lastIpHeader = ipHeader
            } else {
                if (tcpHeader.acknowledgementNumber <= transmissionControlBlock!!.snd_una.value) {
                    // ignore duplicate ACKs
                    logger.debug("Duplicate ACK received, ignoring: $tcpHeader")
                }
                if (tcpHeader.acknowledgementNumber > transmissionControlBlock!!.snd_nxt) {
                    // acking something not yet sent: ack, drop and return
                    logger.error("ACKing something not yet sent: $tcpHeader")
                    // not sure if we send the ack / seq with the transmissionControlBlock values
                    //   or the values from the incoming packet (spec is unclear)
                    return listOf(
                        TcpHeaderFactory.createAckPacket(
                            ipHeader,
                            tcpHeader,
                            seqNumber = transmissionControlBlock!!.snd_nxt,
                            ackNumber = transmissionControlBlock!!.rcv_nxt,
                            transmissionControlBlock = transmissionControlBlock,
                        ),
                    )
                }
            }
        } else {
            // if the ACK bit is off, drop the segment and return
            return emptyList<Packet>()
        }

        // 6th check the urg bit
        // TOOD: might need to not return above in order to actually get. Perhaps the "stop processing" means to not continue with these steps and return
        if (tcpHeader.isUrg()) {
            // This should not occur since a FIN has been received from the
            //            remote side.  Ignore the URG.
            logger.warn("Got URG packet when not expected, ignoring: $this")
        }

        // 7th: process the segment text
        val payloadSize = ipHeader.getPayloadLength() - tcpHeader.getHeaderLength()
        if (payloadSize > 0u || payload.isNotEmpty()) {
            logger.warn("Payload not empty in TIME_WAIT state, ignoring: $this")
        }

        // 8th: check the FIN bit
        checkFinBit(ipHeader, tcpHeader, packets)
        return packets
    }

    /**
     * This should be called after we accept an ACK in order to go back through the retransmit
     * queue and prune any packets that have been fully acknowledged. This has been pulled out of
     * `establishedProcessAck` because it must be done when we accept the SYN-ACK packet which is
     * not considered fully established yet.
     */
    private fun removeAckedPacketsFromRetransmit() {
        // remove all packets from the retransmit queue which have been fully acknowledged
        // https://www.rfc-editor.org/rfc/rfc6298.html
        // (5.3) When an ACK is received that acknowledges new data, restart the
        //         retransmission timer so that it will expire after RTO seconds
        //         (for the current value of RTO).
        rtoJob?.cancel()
        rtoJob = null
        startRtoTimer()

        while (retransmitQueue.isNotEmpty()) {
            // may be null if the session is shutting down
            val packet = retransmitQueue.peek() ?: break
            val previousTcpHeader = packet.nextHeaders as TcpHeader

            if (previousTcpHeader.sequenceNumber + packet.payload!!.size.toUInt()
                <= transmissionControlBlock!!.snd_una.value
            ) {
                logger.trace(
                    "Removing packet with seq: ${previousTcpHeader.sequenceNumber} " +
                        "from retransmit queue, snd_una: ${transmissionControlBlock!!.snd_una.value}",
                )
                // if the queue has been removed already, // this is a no-op
                retransmitQueue.remove(packet)
            } else {
                break
            }
        }

        // https://www.rfc-editor.org/rfc/rfc6298.html
        // (5.2) When all outstanding data has been acknowledged, turn off the
        //         retransmission timer.
        if (retransmitQueue.isEmpty()) {
            rtoJob?.cancel()
            rtoJob = null
        }
    }

    /**
     * This function is called when an ACK is received to update the send window size based on
     * what was received in the ack packet. It also updates wl1 which was the sequence of the
     * last window update, and wl2 which was the ack used for the last update.
     *
     * TODO: make sure this makes sense with wraparound
     */
    private fun updateSendWindow(tcpHeader: TcpHeader) {
        // update send window
        if (transmissionControlBlock!!.snd_wl1 < tcpHeader.sequenceNumber ||
            (
                transmissionControlBlock!!.snd_wl1 == tcpHeader.sequenceNumber &&
                    transmissionControlBlock!!.snd_wl2 <= tcpHeader.acknowledgementNumber
            )
        ) {
            transmissionControlBlock!!.snd_wnd = tcpHeader.windowSize
            transmissionControlBlock!!.snd_wl1 = tcpHeader.sequenceNumber
            transmissionControlBlock!!.snd_wl2 = tcpHeader.acknowledgementNumber
        }
    }

    /**
     * This function is called when an ACK is received to update the congestion state of the
     * cwnd. This is based on the congestion control algorithm described in RFC 2581:
     * https://www.rfc-editor.org/rfc/rfc2581
     */
    private fun updateCongestionState() {
        if (transmissionControlBlock!!.congestionState == TcpCongestionState.SLOW_START) {
            // During slow start, a TCP increments cwnd by at most SMSS bytes for
            //   each ACK received that acknowledges new data.  Slow start ends when
            //   cwnd exceeds ssthresh (or, optionally, when it reaches it, as noted
            //   above) or when congestion is observed.
            if (transmissionControlBlock!!.cwnd < transmissionControlBlock!!.ssthresh) {
                transmissionControlBlock!!.cwnd += mss.toInt()
                logger.debug("Incrementing cwnd in slow start to ${transmissionControlBlock!!.cwnd}")
            } else {
                logger.debug("Transitioning to congestion avoidance")
                transmissionControlBlock!!.congestionState = TcpCongestionState.CONGESTION_AVOIDANCE
            }
        } else if (transmissionControlBlock!!.congestionState == TcpCongestionState.CONGESTION_AVOIDANCE) {
            // During congestion avoidance, cwnd is incremented by 1 full-sized
            //   segment per round-trip time (RTT).  Congestion avoidance continues
            //   until congestion is detected.  One formula commonly used to update
            //   cwnd during congestion avoidance is given in equation 2:
            // cwnd += SMSS*SMSS/cwnd
            val incrementValue = mss.toInt() * mss.toInt() / transmissionControlBlock!!.cwnd
            if (incrementValue == 0) {
                // Implementation Note: Since integer arithmetic is usually used in TCP
                //   implementations, the formula given in equation 2 can fail to increase
                //   cwnd when the congestion window is very large (larger than
                //   SMSS*SMSS).  If the above formula yields 0, the result SHOULD be
                //   rounded up to 1 byte.
                transmissionControlBlock!!.cwnd++
            } else {
                transmissionControlBlock!!.cwnd += incrementValue
            }
            logger.debug("Incrementing cwnd in congestion avoidance to ${transmissionControlBlock!!.cwnd}")
        }
    }

    fun updateTimestamp(tcpHeader: TcpHeader) {
        // https://www.rfc-editor.org/rfc/rfc6298.txt
        // When a subsequent RTT measurement R' is made, a host MUST set
        val timestamp = TcpOptionTimestamp.maybeTimestamp(tcpHeader)
        if (timestamp != null) {
            val ackTimestamp = timestamp.tsecr
            val now = System.currentTimeMillis().toUInt()
            // logger.debug("ACK TIMESTAMP: $ackTimestamp NOW: $now")
            val r = (now.toDouble() - ackTimestamp.toDouble()) / 1000
            transmissionControlBlock!!.rttvar = ((1 - BETA) * transmissionControlBlock!!.rttvar) + (
                BETA *
                    abs(
                        transmissionControlBlock!!.srtt - r,
                    )
            )
            transmissionControlBlock!!.srtt = ((1 - ALPHA) * transmissionControlBlock!!.srtt) + (ALPHA * r)
            transmissionControlBlock!!.rto = max(1.0, transmissionControlBlock!!.srtt + max(G, K * transmissionControlBlock!!.rttvar))
            // logger.debug("timer R: $R RTTVAR: ${transmissionControlBlock!!.rttvar} SRTT: ${transmissionControlBlock!!.srtt} RTO: ${transmissionControlBlock!!.rto}")
        } else {
            logger.warn("No timestamp option in packet, not updating timestamp")
        }
    }

    private fun logRecvWindow(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
    ) {
        val segmentLength = ipHeader.getPayloadLength() - tcpHeader.getHeaderLength()
        logger.debug(
            "seg.seq: ${tcpHeader.sequenceNumber} seg.length: $segmentLength " +
                "seg.seq + seq.length-1: ${(tcpHeader.sequenceNumber + segmentLength - 1u) % UInt.MAX_VALUE }",
        )
        logger.debug(
            "rcv.wnd: ${transmissionControlBlock!!.rcv_wnd} " +
                "rcv.nxt: ${transmissionControlBlock!!.rcv_nxt} " +
                "rcv.next + rcv.wnd: ${(transmissionControlBlock!!.rcv_nxt + transmissionControlBlock!!.rcv_wnd) % UInt.MAX_VALUE} ",
        )
    }

    /**
     * First check sequence number: 3.10.7.4. Other States
     *
     * Returns true if we can proceed, false otherwise. If we return false, we should return the
     * packets in the packet list and stop processing the incoming packet.
     */
    private fun sequenceCheck(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        packets: MutableList<Packet>,
    ): Boolean {
        val sequenceAcceptable = isSequenceAcceptable(ipHeader, tcpHeader)

        if (!sequenceAcceptable) {
            if (tcpHeader.isRst()) {
                logger.warn("Sequence not acceptable, but RST bit set, doing further tests")
                return true
            } else if (tcpState.value == TcpState.TIME_WAIT && tcpHeader.isSyn()) {
                logger.warn("Sequence not acceptable, but SYN bit set and we're in TIME_WAIT state, doing further tests")
                return true
            } else {
                logger.warn("Sequence not acceptable, and RST bit not set, sending ACK")
                val ack =
                    TcpHeaderFactory.createAckPacket(
                        ipHeader,
                        tcpHeader,
                        seqNumber = transmissionControlBlock!!.snd_nxt,
                        ackNumber = transmissionControlBlock!!.rcv_nxt,
                        transmissionControlBlock = transmissionControlBlock,
                    )
                packets.add(ack)
                return false
            }
        } else {
            return true
        }
    }

    private fun isSequenceAcceptable(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
    ): Boolean {
        val segmentLength = ipHeader.getPayloadLength() - tcpHeader.getHeaderLength()
        // case 1:
        if (segmentLength == 0u && transmissionControlBlock!!.rcv_wnd == 0u.toUShort()) {
            if (tcpHeader.sequenceNumber == transmissionControlBlock!!.rcv_nxt) {
                return true
            } else {
                logger.warn("CASE 1: not acceptable")
                logRecvWindow(ipHeader, tcpHeader)
                return false
            }
        }

        // case 2:
        if (segmentLength == 0u && transmissionControlBlock!!.rcv_wnd > 0u) {
            // if we use longs, we can avoid the wraparound issue
            val rcvWndEnd = transmissionControlBlock!!.rcv_nxt.toULong() + transmissionControlBlock!!.rcv_wnd.toULong()
            if (tcpHeader.sequenceNumber >= transmissionControlBlock!!.rcv_nxt && tcpHeader.sequenceNumber < rcvWndEnd) {
                return true
            } else {
                logger.warn("CASE 2: not acceptable")
                logRecvWindow(ipHeader, tcpHeader)
                return false
            }
        }

        // case 3:
        if (segmentLength > 0u && transmissionControlBlock!!.rcv_wnd == 0u.toUShort()) {
            logger.warn("CASE 3: not acceptable")
            logRecvWindow(ipHeader, tcpHeader)
            return false
        }

        // case 4:
        if (segmentLength > 0u && transmissionControlBlock!!.rcv_wnd > 0u) {
            // if we use longs, we can avoid the wraparound issue
            val rcvWndEnd = transmissionControlBlock!!.rcv_nxt.toULong() + transmissionControlBlock!!.rcv_wnd.toULong()
            val segmentEnd = (tcpHeader.sequenceNumber.toULong() + segmentLength.toULong() - 1u)

            // case 4a: start of segment is in window
            if (tcpHeader.sequenceNumber >= transmissionControlBlock!!.rcv_nxt && tcpHeader.sequenceNumber < rcvWndEnd) {
                return true
            }

            // case 4b: end of segment is in window
            if (segmentEnd < rcvWndEnd) {
                return true
            }

            logger.warn("CASE 4: not acceptable")
            logRecvWindow(ipHeader, tcpHeader)
            return false
        }

        logger.error("SHOULDN'T HAVE GOT HERE")
        logRecvWindow(ipHeader, tcpHeader)
        return false
    }

    /**
     * Checks the RST bit. If its set, we may transition state, and optionally add a packet to be
     * sent back to the client, depending on the current state.
     *
     * Returns true if we can proceed, false otherwise. If we return false, we should stop processing
     * the packet and return the packets in the packet list.
     */
    private fun checkRstBit(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        packets: MutableList<Packet>,
    ): Boolean {
        if (tcpHeader.isRst()) {
            if (tcpState.value == TcpState.SYN_RECEIVED) {
                // TODO: consider RFC 5961 - which we are not for now
                if (transmissionControlBlock!!.passive_open) {
                    transmissionControlBlock!!.last_timestamp = TcpOptionTimestamp.maybeTimestamp(tcpHeader)
                    logger.debug("Got RST in SYN_RECEIVED state with passive open, transitioning to LISTEN")
                    outgoingBuffer.clear()
                    tcpState.value = TcpState.LISTEN
                    return false
                } else {
                    transmissionControlBlock!!.last_timestamp = TcpOptionTimestamp.maybeTimestamp(tcpHeader)
                    logger.debug("Got RST in SYN_RECEIVED state with active open, transitioning to CLOSED")
                    tcpState.value = TcpState.CLOSED
                    isClosed = true
                    transmissionControlBlock = null
                    outgoingBuffer.clear()
                    return false
                }
            } else if (tcpState.value == TcpState.ESTABLISHED ||
                tcpState.value == TcpState.FIN_WAIT_1 ||
                tcpState.value == TcpState.FIN_WAIT_2 ||
                tcpState.value == TcpState.CLOSE_WAIT
            ) {
                // 1)  If the RST bit is set and the sequence number is outside
                //             the current receive window, silently drop the segment.
                if (tcpHeader.sequenceNumber < transmissionControlBlock!!.rcv_nxt ||
                    tcpHeader.sequenceNumber > transmissionControlBlock!!.rcv_nxt + transmissionControlBlock!!.rcv_wnd
                ) {
                    logger.warn(
                        "Received RST in ${tcpState.value} state, but sequence number is " +
                            "outside of the receive window, dropping: $tcpHeader",
                    )
                    return false
                }
                // 2)  If the RST bit is set and the sequence number exactly
                //             matches the next expected sequence number (RCV.NXT), then
                //             TCP endpoints MUST reset the connection in the manner
                //             prescribed below according to the connection state.
                //
                // If the RST bit is set, then any outstanding RECEIVEs and
                //            SEND should receive "reset" responses.  All segment queues
                //            should be flushed.  Users should also receive an unsolicited
                //            general "connection reset" signal.  Enter the CLOSED state,
                //            delete the TCB, and return.
                if (tcpHeader.sequenceNumber == transmissionControlBlock!!.rcv_nxt) {
                    logger.warn(
                        "Received RST in ${tcpState.value} state, transitioning to CLOSED: {}",
                        tcpHeader,
                    )
                    // todo: flush of buffers
                    tcpState.value = TcpState.CLOSED
                    isClosed = true
                    transmissionControlBlock = null
                    outgoingBuffer.clear()
                    return false
                }

                // 3)  If the RST bit is set and the sequence number does not
                //             exactly match the next expected sequence value, yet is
                //             within the current receive window, TCP endpoints MUST send
                //             an acknowledgment (challenge ACK):
                //
                //             <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                //
                //             After sending the challenge ACK, TCP endpoints MUST drop
                //             the unacceptable segment and stop processing the incoming
                //             packet further.  Note that RFC 5961 and Errata ID 4772 [99]
                //             contain additional considerations for ACK throttling in an
                //             implementation.
                logger.warn("Received RST in ${tcpState.value} state, sending challenge ACK: $tcpHeader")
                val ack =
                    TcpHeaderFactory.createAckPacket(
                        ipHeader,
                        tcpHeader,
                        seqNumber = transmissionControlBlock!!.snd_nxt,
                        ackNumber = transmissionControlBlock!!.rcv_nxt,
                        transmissionControlBlock = transmissionControlBlock,
                    )
                packets.add(ack)
                return false
            } else if (tcpState.value == TcpState.CLOSING || tcpState.value == TcpState.LAST_ACK || tcpState.value == TcpState.TIME_WAIT) {
                // If the RST bit is set, then enter the CLOSED state, delete the TCB, and return
                tcpState.value = TcpState.CLOSED
                isClosed = true
                transmissionControlBlock = null
                outgoingBuffer.clear()
                return false
            } else if (tcpState.value == TcpState.CLOSED || tcpState.value == TcpState.LISTEN) {
                return false
            } else if (tcpState.value == TcpState.SYN_SENT) {
                if (tcpHeader.sequenceNumber == transmissionControlBlock!!.rcv_nxt) {
                    logger.debug(
                        "Received RST in SYN_SENT state, transitioning to CLOSED: {}",
                        tcpHeader,
                    )
                    // RFC9293: If the RST bit is set, the connection should be aborted and the TCB should be deleted
                    tcpState.value = TcpState.CLOSED
                    isClosed = true
                    transmissionControlBlock = null
                    outgoingBuffer.clear()
                    return false
                } else {
                    // drop the segment and return
                    logger.warn(
                        "Received RST in SYN_SENT state, but sequence number doesn't match, dropping segment and returning: $tcpHeader",
                    )
                    return false
                }
            } else {
                logger.error("SHOULDN'T HAVE GOT HERE: state: ${tcpState.value}")
                return false
            }
        } else {
            return true
        }
    }

    /**
     * Checks the Syn bit in the incoming packet. If the syn bit is set, we may transition state,
     * and optionally add a packet to be sent back to the client, depending on the current state.
     *
     * Returns true if we can proceed, false otherwise. If we return false, we should stop processing
     */
    private fun checkSynBit(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        payload: ByteArray,
        packets: MutableList<Packet>,
    ): Boolean {
        if (tcpHeader.isSyn()) {
            if (tcpState.value == TcpState.SYN_RECEIVED) {
                logger.debug("Got SYN in SYN_RECEIVED state")
                if (transmissionControlBlock!!.passive_open) {
                    transmissionControlBlock!!.last_timestamp =
                        TcpOptionTimestamp.maybeTimestamp(tcpHeader)
                    logger.debug(
                        "Got SYN in SYN_RECEIVED state, transitioning to LISTEN: {}",
                        tcpHeader,
                    )
                    tcpState.value = TcpState.LISTEN
                    return false
                } else {
                    logger.debug(
                        "Got SYN in SYN_RECEIVED state, sending Challenge ACK: {}",
                        tcpHeader,
                    )
                    // RFC5961: recommends that in sync states, we should send a "challenge ACK" to
                    //   the remote peer. If this doesn't work, the RC793 recommends entering CLOSED
                    //   state, deleting the TCP, queues flushed.
                    //   After ACK-ing the segment, it should be dropped, and stop processing
                    //     further, ie no data processing. (and possibly no further processing of
                    //       any additional segments? unclear)
                    val ack =
                        TcpHeaderFactory.createAckPacket(
                            ipHeader,
                            tcpHeader,
                            seqNumber = transmissionControlBlock!!.snd_nxt,
                            ackNumber = transmissionControlBlock!!.rcv_nxt,
                            transmissionControlBlock = transmissionControlBlock,
                        )
                    packets.add(ack)
                    return false
                }
            } else if (tcpState.value == TcpState.TIME_WAIT) {
                val previousTimestamp = (transmissionControlBlock?.last_timestamp?.tsval ?: 0u)
                val currentTimestamp = TcpOptionTimestamp.maybeTimestamp(tcpHeader)?.tsval ?: 0u
                if (currentTimestamp > previousTimestamp) {
                    logger.debug(
                        "Received SYN in TIME_WAIT state with acceptable timestamp " +
                            "($previousTimestamp < $currentTimestamp), transitioning to " +
                            "SYN-RECEIVED: $tcpHeader",
                    )
                    tcpState.value = TcpState.LISTEN
                    session.close(true, packet = Packet(ipHeader, tcpHeader, payload))
                    return false
                } else {
                    logger.debug(
                        "Received SYN in TIME_WAIT state with unacceptable timestamp " +
                            "($previousTimestamp >= $currentTimestamp), sending challenge" +
                            "ACK: $tcpHeader",
                    )
                    // RFC5961: recommends that in sync states, we should send a "challenge ACK" to
                    //   the remote peer. If this doesn't work, the RC793 recommends entering CLOSED
                    //   state, deleting the TCP, queues flushed.
                    //   After ACK-ing the segment, it should be dropped, and stop processing
                    //     further, ie no data processing. (and possibly no further processing of
                    //       any additional segments? unclear)
                    val ack =
                        TcpHeaderFactory.createAckPacket(
                            ipHeader,
                            tcpHeader,
                            seqNumber = transmissionControlBlock!!.snd_nxt,
                            ackNumber = transmissionControlBlock!!.rcv_nxt,
                            transmissionControlBlock = transmissionControlBlock,
                        )
                    packets.add(ack)
                    return false
                }
            } else if (tcpState.value == TcpState.ESTABLISHED ||
                tcpState.value == TcpState.FIN_WAIT_1 ||
                tcpState.value == TcpState.FIN_WAIT_2 ||
                tcpState.value == TcpState.CLOSE_WAIT ||
                tcpState.value == TcpState.CLOSING ||
                tcpState.value == TcpState.LAST_ACK
            ) {
                logger.error("Got SYN in ${tcpState.value} state, sending challenge ACK: $tcpHeader")
                // RFC5961: recommends that in sync states, we should send a "challenge ACK" to
                //   the remote peer. If this doesn't work, the RC793 recommends entering CLOSED
                //   state, deleting the TCP, queues flushed.
                //   After ACK-ing the segment, it should be dropped, and stop processing
                //     further, ie no data processing. (and possibly no further processing of
                //       any additional segments? unclear)
                val ack =
                    TcpHeaderFactory.createAckPacket(
                        ipHeader,
                        tcpHeader,
                        seqNumber = transmissionControlBlock!!.snd_nxt,
                        ackNumber = transmissionControlBlock!!.rcv_nxt,
                        transmissionControlBlock = transmissionControlBlock,
                    )
                packets.add(ack)
                return false
            } else {
                logger.warn("Got SYN in unexpected state: $tcpState")
                return false
            }
        }
        return true
    }

    /**
     * Checks the Ack bit in the incoming packet. If the ack bit is set, we may transition state,
     * and optionally add a packet to be sent back to the client, depending on the current state.
     *
     * If the packet ACKs something in the retransmit queue, we will remove the packets from the
     * retransmit queue that have been fully acknowledged.
     *
     * Returns true if we can proceed, false otherwise. If we return false, we should stop processing
     * the packet and return the packets in the packet list.
     */
    private fun checkAckBit(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        packets: MutableList<Packet>,
    ): Boolean {
        if (tcpHeader.isAck()) {
            if (isAckAcceptable(tcpHeader)) {
                logger.debug("Received ACK in ${tcpState.value} state, updating snd_una: $tcpHeader")
                transmissionControlBlock!!.last_timestamp = TcpOptionTimestamp.maybeTimestamp(tcpHeader)
                transmissionControlBlock!!.snd_una.value = tcpHeader.acknowledgementNumber
                updateTimestamp(tcpHeader)
                removeAckedPacketsFromRetransmit()
                updateCongestionState()
                updateSendWindow(tcpHeader)
                return true
            } else {
                logger.debug("Received unacceptable ACK in ${tcpState.value} state")
                if (tcpHeader.acknowledgementNumber <= transmissionControlBlock!!.snd_una.value) {
                    // ignore duplicate ACKs
                    logger.debug("Duplicate ACK received in ${tcpState.value} state, ignoring: $tcpHeader")
                    // we return true because we don't want to necessarily drop the packet if the ACK is duplicate. We
                    // will only do that if we've already received the sequence number. All this does is prevent us from
                    // updating windows, etc.
                    return true
                }
                if (tcpHeader.acknowledgementNumber > transmissionControlBlock!!.snd_nxt) {
                    // acking something not yet sent: ack, drop and return
                    logger.error("ACKing something not yet sent in ${tcpState.value} state: $tcpHeader")
                    // not sure if we send the ack / seq with the transmissionControlBlock values
                    //   or the values from the incoming packet (spec is unclear)
                    val ack =
                        TcpHeaderFactory.createAckPacket(
                            ipHeader,
                            tcpHeader,
                            seqNumber = transmissionControlBlock!!.snd_nxt,
                            ackNumber = transmissionControlBlock!!.rcv_nxt,
                            transmissionControlBlock = transmissionControlBlock,
                        )
                    packets.add(ack)
                    return false
                }
            }
        } else {
            // if the ACK bit isn't set, we shouldn't proceed
            return false
        }
        logger.warn("Shouldn't have got here in state: ${tcpState.value} state")
        return false
    }

    /**
     * This can't just simply check if snd.una < ack <= snd.nxt because of wraparound. This must
     * handle the edge cases where where snd.una > snd.nxt.
     */
    private fun isAckAcceptable(tcpHeader: TcpHeader): Boolean {
        if (transmissionControlBlock!!.snd_una.value <= transmissionControlBlock!!.snd_nxt) {
            val result =
                tcpHeader.acknowledgementNumber > transmissionControlBlock!!.snd_una.value &&
                    tcpHeader.acknowledgementNumber <= transmissionControlBlock!!.snd_nxt
            if (!result) {
                logger.debug(
                    "snd_una: ${transmissionControlBlock!!.snd_una.value} ack: " +
                        "${tcpHeader.acknowledgementNumber} snd_nxt: " +
                        "${transmissionControlBlock!!.snd_nxt}",
                )
            }
            return result
        } else {
            logger.debug(
                "Wraparound case: snd_una: ${transmissionControlBlock!!.snd_una.value} > snd_nxt: ${transmissionControlBlock!!.snd_nxt}",
            )
            return tcpHeader.acknowledgementNumber > transmissionControlBlock!!.snd_una.value ||
                tcpHeader.acknowledgementNumber <= transmissionControlBlock!!.snd_nxt
        }
    }

    /**
     * We can really only receive data in the ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2 states. If
     * we receive data in any other state, we should ignore it and return an empty list.
     *
     * If we have already received the segment, we should ignore it and return an empty list.
     *
     * Otherwise, the segment is accepted and we will take ownership of it (ie, write it to the
     * channel).
     *
     * If there is a failure to write to the channel, we will try to teardown the session and may
     * return a FIN packet to close the session.
     *
     * We only send an ACK for accepted data if the PSH bit is set, otherwise we wait for possible
     * return traffic to send the ACK, or until the 500ms timer expires.
     */
    private fun processText(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        payload: ByteArray,
        packets: MutableList<Packet>,
    ): Boolean {
        if (tcpHeader.sequenceNumber < transmissionControlBlock!!.rcv_nxt) {
            logger.error("ALREADY RECEIVED SEGMENT, SHOULD IGNORE: $tcpHeader")
            return false
        }
        val payloadSize = ipHeader.getPayloadLength() - tcpHeader.getHeaderLength()
        assert(payloadSize == payload.size.toUInt())
        if (payload.isNotEmpty()) {
            if (tcpHeader.isPsh()) {
                // this needs to happen before we write to the channel or we could
                // miss the PSH at the tcp client
                session.isPsh.set(true)
            }
            try {
                val buffer = ByteBuffer.wrap(payload)
                while (buffer.hasRemaining()) {
                    if (session.channel is BidirectionalByteChannel) {
                        // tcp client case
                        session.channel.write(buffer)
                    } else {
                        // anon proxy case
                        session.outgoingToInternet.write(buffer)
                    }
                }
                session.readyToWrite()
            } catch (e: Exception) {
                logger.warn("Error writing to channel: $e, shutting down session")
                val finPacket = session.teardown(!swapSourceDestination, requiresLock = false)
                if (finPacket != null) {
                    enqueueRetransmit(finPacket)
                    packets.add(finPacket)
                    return false
                } else {
                    return false
                }
            }
            logger.debug("Accepted ${payload.size} bytes of data")
            transmissionControlBlock!!.rcv_nxt += payload.size.toUInt()
            val ack =
                TcpHeaderFactory.createAckPacket(
                    ipHeader,
                    tcpHeader,
                    seqNumber = transmissionControlBlock!!.snd_nxt,
                    ackNumber = transmissionControlBlock!!.rcv_nxt,
                    transmissionControlBlock = transmissionControlBlock,
                )
            if (tcpHeader.isPsh()) {
                logger.debug(
                    "Received PSH in ESTABLISHED state, sending ACK " +
                        "immediately SEQ: " +
                        "${(ack.nextHeaders as TcpHeader).sequenceNumber} ACK: " +
                        "${(ack.nextHeaders as TcpHeader).acknowledgementNumber}",
                )
                packets.add(ack)
            } else {
                setupLatestAckJob(ack)
            }
        }
        return true
    }

    /**
     * Attempts to enqueue all of the data in the buffer into the outgoing buffer. If the buffer fills up, it will
     * enqueue as much as it can. Returns the number of bytes enqueued. Also sets the position of the buffer to the
     * next byte to be read (ie, the byte after the last enqueued byte)
     */
    fun enqueueOutgoingData(buffer: ByteBuffer): Int {
        return runBlocking {
            val bytesToEnqueue =
                outgoingMutex.withLock {
                    // logger.debug("ENQ: Outgoing buffer position: ${outgoingBuffer.position()} limit: ${outgoingBuffer.limit()}")
                    // if we've previously compacted we won't get into here (just to reset us from read mode to write mode)
                    if (outgoingBuffer.limit() != outgoingBuffer.capacity()) {
                        // this should set us up so that we are writing right after the last byte we wrote previously
                        // with a limit of the rest of the buffer
                        outgoingBuffer.compact()
//                        logger.debug(
//                            "ENQ: After compact Outgoing buffer position: ${outgoingBuffer.position()} limit: ${outgoingBuffer.limit()}",
//                        )
                    }
                    val bytesToEnqueue = min(buffer.remaining(), outgoingBuffer.remaining())
                    outgoingBuffer.put(buffer.array(), buffer.position(), bytesToEnqueue)
                    buffer.position(buffer.position() + bytesToEnqueue)
//                    logger.debug("ENQ: After write Outgoing buffer position: ${outgoingBuffer.position()} limit: ${outgoingBuffer.limit()}")
                    return@withLock bytesToEnqueue
                }
            return@runBlocking bytesToEnqueue
        }
    }

    fun availableOutgoingBufferSpace(): Int {
        return runBlocking {
            val remaining =
                outgoingMutex.withLock {
                    outgoingBuffer.remaining()
                }
            return@runBlocking remaining
        }
    }

    fun outgoingBytesToSend(): Int {
        return runBlocking {
            outgoingMutex.withLock {
                return@runBlocking outgoingBuffer.position()
            }
        }
    }

    /**
     * We assume that the buffer is positioned after the data to be encapsulated. Once it's been encapsulated, it's
     * removed from this buffer. The encapsulated packets are returned and also stored in the retransmit queue. Packets
     * are cleared from the retransmit queue when they are fully acknowledged.
     *
     * TODO: determine what happens if they are partially acknowledged.
     *
     * @param swapSourceDestination if true, the source and destination addresses and ports will be swapped in the
     * encapsulated packets. The only time we want to do this is when we are sending packets from the tcp into the proxy
     * server. This is because the source and destination are reversed in the proxy server.
     */
    fun encapsulateOutgoingData(
        swapSourceDestination: Boolean = false,
        requiresLock: Boolean,
    ): List<Packet> {
        val packets =
            runBlocking {
                val packets = ArrayList<Packet>()
                val sourceAddress = if (swapSourceDestination) session.getDestinationAddress() else session.getSourceAddress()
                val destinationAddress = if (swapSourceDestination) session.getSourceAddress() else session.getDestinationAddress()
                val sourcePort = if (swapSourceDestination) session.getDestinationPort() else session.getSourcePort()
                val destinationPort = if (swapSourceDestination) session.getSourcePort() else session.getDestinationPort()

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

                outgoingMutex.withLock {
                    if (requiresLock) {
                        logger.warn("ENCAP PACKETS TAKING LOCK")
                        tcbMutex.lock()
                    }
                    do {
                        // logger.debug("ENC before flip Buffer position: ${outgoingBuffer.position()} limit: ${outgoingBuffer.limit()}")
                        var isPush = false
                        outgoingBuffer.flip()
                        // logger.debug("ENC after flip Buffer position: ${outgoingBuffer.position()} limit: ${outgoingBuffer.limit()}")
                        // logger.debug("REMAINING: ${session.sendBuffer.remaining()}, MSS: ${session.tcpStateMachine.mss}")
                        // logger.debug("Session buffer: \n{}", BufferUtil.toHexString(session.sendBuffer, 0, session.sendBuffer.limit()))
                        if (outgoingBuffer.remaining() == 0) {
                            // handle case where we have an empty buffer (the first iteration of
                            // the loop will show remaining because its before we've flipped the first time
                            outgoingBuffer.compact()
                            break
                        }
                        val cwnd =
                            session.tcpStateMachine.transmissionControlBlock!!
                                .cwnd
                                .toUInt()
                        val outstandingBytes = session.tcpStateMachine.transmissionControlBlock!!.outstandingBytes()
                        if (cwnd <= outstandingBytes) {
                            logger.warn("Hit cwnd limit, outstanding bytes: $outstandingBytes holding off on more packets for now")
                            outgoingBuffer.compact()
                            if (requiresLock) {
                                tcbMutex.unlock()
                                logger.warn("ENCAP PACKETS LOCK RELEASED")
                            }
                            return@runBlocking packets
                        }
                        val availableSendBytes = cwnd - outstandingBytes

                        // logger.debug("ENC Available send bytes: $availableSendBytes")
                        val adjustedForMssBytes = min(availableSendBytes, mss.toUInt())
                        // logger.debug("ENC Adjusted for Mss: $adjustedForMssBytes")
                        val payloadSize = min(adjustedForMssBytes.toInt(), outgoingBuffer.remaining())
                        // logger.debug("ENC Actual send bytes (adjusted for buffer remaining): $payloadSize")
                        val payloadCopy = ByteArray(payloadSize)
                        outgoingBuffer.get(payloadCopy)
                        // logger.debug("ENC after payload get position: ${outgoingBuffer.position()} limit: ${outgoingBuffer.limit()}")
                        if (outgoingBuffer.remaining() == 0) {
                            isPush = true
                            outgoingBuffer.clear()
                            // logger.debug("ENC after clear position: ${outgoingBuffer.position()} limit: ${outgoingBuffer.limit()}")
                            if (session.tearDownPending.get()) {
                                logger.debug("TEARDOWN PENDING, sending FIN")
                                val finPacket = session.teardown(!swapSourceDestination, requiresLock = false)
                                if (finPacket != null) {
                                    enqueueRetransmit(finPacket)
                                    packets.add(finPacket)
                                }
                            }
                        } else {
                            outgoingBuffer.compact()
                            // logger.debug("ENC after compact position: ${outgoingBuffer.position()} limit: ${outgoingBuffer.limit()}")
                        }

                        val latestAckNumber =
                            if (latestAck != null) {
                                (latestAck!!.nextHeaders as TcpHeader).acknowledgementNumber
                            } else {
                                transmissionControlBlock!!.rcv_nxt
                            }
                        delayedAckJob?.cancel()
                        delayedAckJob = null
                        latestAck = null
                        val packet =
                            TcpHeaderFactory.createAckPacket(
                                ipHeader = ipHeader,
                                tcpHeader = tcpHeader,
                                seqNumber = session.tcpStateMachine.transmissionControlBlock!!.snd_nxt,
                                ackNumber = latestAckNumber,
                                isPsh = isPush,
                                payload = ByteBuffer.wrap(payloadCopy),
                                transmissionControlBlock = transmissionControlBlock,
                            )

                        if (session.tcpStateMachine.transmissionControlBlock!!
                                .snd_nxt
                                .toULong() + payloadSize.toULong() >
                            UInt.MAX_VALUE.toULong()
                        ) {
                            logger.debug("Wraparound case in encapsulateOutgoingData")
                            val carryOver =
                                (
                                    session.tcpStateMachine.transmissionControlBlock!!
                                        .snd_nxt
                                        .toULong() + payloadSize.toULong()
                                ) -
                                    UInt.MAX_VALUE.toULong()
                            session.tcpStateMachine.transmissionControlBlock!!.snd_nxt = carryOver.toUInt()
                        } else {
                            session.tcpStateMachine.transmissionControlBlock!!.snd_nxt += payloadSize.toUShort()
                        }
                        packets.add(packet)
                    } while (outgoingBuffer.hasRemaining())
                    if (requiresLock) {
                        tcbMutex.unlock()
                        logger.warn("ENCAP PACKETS LOCK RELEASED")
                    }

                    if (outgoingBuffer.remaining() > 0) {
                        // let the channel know we're ready to read again
                        if (session.channel is SocketChannel) {
                            synchronized(session.changeRequests) {
                                session.changeRequests.add(
                                    ChangeRequest(
                                        session.channel as SocketChannel,
                                        ChangeRequest.CHANGE_OPS,
                                        OP_READ,
                                    ),
                                )
                            }
                        } else if (session.channel is DatagramChannel) {
                            synchronized(session.changeRequests) {
                                session.changeRequests.add(
                                    ChangeRequest(
                                        session.channel as DatagramChannel,
                                        ChangeRequest.CHANGE_OPS,
                                        OP_READ,
                                    ),
                                )
                            }
                        }
                    }
                }
                if (packets.isNotEmpty()) {
                    if (rtoJob == null) {
                        startRtoTimer()
                    }
                }
                return@runBlocking packets
            }
        return packets
    }

    /**
     * When the retransmission timer expires, do the following:
     *
     *        (5.4) Retransmit the earliest segment that has not been acknowledged
     *              by the TCP receiver.
     *
     *        (5.5) The host MUST set RTO <- RTO * 2 ("back off the timer").  The
     *              maximum value discussed in (2.5) above may be used to provide
     *              an upper bound to this doubling operation.
     *
     *        (5.6) Start the retransmission timer, such that it expires after RTO
     *              seconds (for the value of RTO after the doubling operation
     *              outlined in 5.5).
     *
     *        (5.7) If the timer expires awaiting the ACK of a SYN segment and the
     *              TCP implementation is using an RTO less than 3 seconds, the RTO
     *              MUST be re-initialized to 3 seconds when data transmission
     *              begins (i.e., after the three-way handshake completes).
     *
     *              This represents a change from the previous version of this
     *              document [PA00] and is discussed in Appendix A.
     *
     *              Note that after retransmitting, once a new RTT measurement is
     *        obtained (which can only happen when new data has been sent and
     *        acknowledged), the computations outlined in Section 2 are performed,
     *        including the computation of RTO, which may result in "collapsing"
     *        RTO back down after it has been subject to exponential back off (rule
     *        5.5).
     *
     *        Note that a TCP implementation MAY clear SRTT and RTTVAR after
     *        backing off the timer multiple times as it is likely that the current
     *        SRTT and RTTVAR are bogus in this situation.  Once SRTT and RTTVAR
     *        are cleared, they should be initialized with the next RTT sample
     *        taken per (2.2) rather than using (2.3).
     */
    private fun startRtoTimer() {
        if (rtoJob == null) {
            rtoJob =
                CoroutineScope(Dispatchers.IO).launch {
                    val rtoExpiry = ((transmissionControlBlock?.rto ?: 0.0) * 1000L).toLong()
                    if (rtoExpiry == 0L) {
                        logger.error("RTO is 0, shouldn't have got here")
                        return@launch
                    }
                    delay(rtoExpiry)
                    if (retransmitQueue.isNotEmpty()) {
                        // we only peek because we want to keep the packet in the queue until we get a positive ack so
                        // it doesn't get lost. It will be removed when we receive a successful ack
                        val retransmitPacket = retransmitQueue.peek()
                        logger.debug("RTO expired after $rtoExpiry ms, retransmitting: $retransmitPacket")
                        session.returnQueue.add(retransmitPacket)
                        // When a TCP sender detects segment loss using the retransmission
                        //   timer, the value of ssthresh MUST be set to no more than the value
                        //   given in equation 3:
                        //
                        //      ssthresh = max (FlightSize / 2, 2*SMSS)            (3)
                        //
                        //   As discussed above, FlightSize is the amount of outstanding data in
                        //   the network.
                        //
                        //   Implementation Note: an easy mistake to make is to simply use cwnd,
                        //   rather than FlightSize, which in some implementations may
                        //   incidentally increase well beyond rwnd.
                        //
                        //   Furthermore, upon a timeout cwnd MUST be set to no more than the loss
                        //   window, LW, which equals 1 full-sized segment (regardless of the
                        //   value of IW).  Therefore, after retransmitting the dropped segment
                        //   the TCP sender uses the slow start algorithm to increase the window
                        //   from 1 full-sized segment to the new value of ssthresh, at which
                        //   point congestion avoidance again takes over.
                        transmissionControlBlock?.ssthresh =
                            max(transmissionControlBlock!!.outstandingBytes().toInt() / 2, 2 * mss.toInt())

                        // set cwnd to 1 full-sized segment
                        transmissionControlBlock?.cwnd = session.tcpStateMachine.mss.toInt()
                    }
                    rtoJob = null
                    startRtoTimer()
                }
        }
    }

    private fun setupLatestAckJob(ack: Packet) {
        latestAck = ack
        if (delayedAckJob == null) {
            delayedAckJob =
                CoroutineScope(Dispatchers.IO).launch {
                    delay(500)
                    if (latestAck != null) {
                        session.returnQueue.add(latestAck!!)
                        latestAck = null
                    }
                    delayedAckJob = null
                }
        }
    }

    fun enqueueRetransmit(packet: Packet) {
        retransmitQueue.add(packet)
    }

    /**
     * Checks the FIN bit, and if it's set, we may transition state, and optionally add a packet
     * to be sent back to the client, depending on the current state.
     */
    fun checkFinBit(
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        packets: MutableList<Packet>,
    ) {
        if (tcpHeader.isFin()) {
            logger.debug("Received FIN in ${tcpState.value} state: $tcpHeader")
            logger.debug("SWAP SRC DEST? $swapSourceDestination")
            transmissionControlBlock!!.last_timestamp = TcpOptionTimestamp.maybeTimestamp(tcpHeader)
            transmissionControlBlock!!.rcv_nxt =
                tcpHeader.sequenceNumber + 1u // advance RCV.NXT over the FIN

            if (tcpState.value == TcpState.SYN_RECEIVED || tcpState.value == TcpState.ESTABLISHED) {
                logger.debug("transitioning to CLOSE_WAIT")
                tcpState.value = TcpState.CLOSE_WAIT
            } else if (tcpState.value == TcpState.FIN_WAIT_1) {
                if (transmissionControlBlock!!.fin_acked) {
                    logger.debug("Received FIN after our FIN has been acked, transition to TIME_WAIT")
                    startTimeWaitTimers()
                } else {
                    logger.debug("Received FIN, but our's hasn't been ACK'd transitioning to CLOSING state")
                    tcpState.value = TcpState.CLOSING
                }
            } else if (tcpState.value == TcpState.FIN_WAIT_2) {
                logger.debug("Received FIN in FIN_WAIT2 state, transitioning to TIME_WAIT")
                startTimeWaitTimers()
            } else if (tcpState.value == TcpState.CLOSE_WAIT || tcpState.value == TcpState.CLOSING || tcpState.value == TcpState.LAST_ACK) {
                logger.debug("Received FIN in ${tcpState.value} state, remaining in CLOSE_WAIT")
            } else if (tcpState.value == TcpState.TIME_WAIT) {
                logger.debug("Received FIN in TIME_WAIT state, restarting TIME_WAIT timer")
                startTimeWaitTimers()
            } else {
                logger.error("SHOULDN'T HAVE GOT HERE: state: ${tcpState.value}")
            }
            transmissionControlBlock!!.last_timestamp = TcpOptionTimestamp.maybeTimestamp(tcpHeader)
            val ackPacket =
                TcpHeaderFactory.createAckPacket(
                    ipHeader,
                    tcpHeader,
                    seqNumber = transmissionControlBlock!!.snd_nxt,
                    ackNumber = transmissionControlBlock!!.rcv_nxt,
                    transmissionControlBlock = transmissionControlBlock,
                )
            packets.add(ackPacket)
            val finPacket = session.teardown(!swapSourceDestination, requiresLock = false)
            if (finPacket != null) {
                enqueueRetransmit(finPacket)
                packets.add(finPacket)
            }
        }
    }

    private fun startTimeWaitTimers() {
        tcpState.value = TcpState.TIME_WAIT
        // cancel other timers
        // TODO: make sure we're cancelling them all
        rtoJob?.cancel()
        rtoJob = null
        if (timeWaitJob != null) {
            timeWaitJob!!.cancel()
        }
        timeWaitJob =
            CoroutineScope(Dispatchers.IO).launch {
                logger.debug("TIME_WAIT timer started")
                delay((2 * MSL * 1000).toLong())
                tcbMutex.withLock {
                    if (tcpState.value == TcpState.TIME_WAIT) {
                        logger.debug("TIME_WAIT timer expired, transitioning to CLOSED")
                        tcpState.value = TcpState.CLOSED
                        isClosed = true
                        transmissionControlBlock = null
                        outgoingBuffer.clear()
                    }
                }
            }
    }
}
