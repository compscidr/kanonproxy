package com.jasonernst.kanonproxy.tcp

import com.jasonernst.knet.transport.tcp.TcpHeader.Companion.DEFAULT_WINDOW_SIZE
import com.jasonernst.knet.transport.tcp.options.TcpOptionTimestamp
import kotlinx.coroutines.flow.MutableStateFlow

/**
 * Represents the Transmission Control Block (TCB) of a TCP connection. See https://www.rfc-editor.org/rfc/rfc9293.txt
 * section 3.3.1 for more information.
 */
data class TransmissionControlBlock(
    // send sequence variables (maybe break into separate class)
    var snd_una: MutableStateFlow<UInt> = MutableStateFlow(0u), // oldest unacknowledged sequence number
    var snd_nxt: UInt = 0u, // next sequence number to be sent
    var snd_wnd: UShort = 0u, // this is set to the remote side's advertised window
    var snd_up: UShort = 0u,
    var snd_wl1: UInt = 0u,
    var snd_wl2: UInt = 0u,
    var iss: UInt = 0u,
    // recv sequence variables (maybe break into separate class)
    var rcv_nxt: UInt = 0u, // next sequence number expected on an incoming segment, and is the left or lower edge of the receive window
    var rcv_wnd: UShort = DEFAULT_WINDOW_SIZE, // this is our receive window which we advertise out to the remote side
    var rcv_up: UShort = 0u,
    var irs: UInt = 0u,
    // extra notes:
    // SEG.SEQ+SEG.LEN-1 is the sequence number of the last data octet in the segment
    // A new acknowledgment (called an "acceptable ack") is one for which
    //   the inequality below holds:
    //
    //      SND.UNA < SEG.ACK =< SND.NXT
    //
    //   A segment on the retransmission queue is fully acknowledged if the
    //   sum of its sequence number and length is less than or equal to the
    //   acknowledgment value in the incoming segment.
    // A segment is judged to occupy a portion of valid receive sequence
    //   space if
    //
    //      RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND (beginning of segment falls in window)
    //
    //   or
    //
    //      RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND (end of segment falls in window)
    // we also have some extra cases due to zero windows, and zero-length segments.
    // RFC 7323: timestamp handling https://www.rfc-editor.org/rfc/rfc7323.txt
    var send_ts_ok: Boolean = false,
    var passive_open: Boolean = false,
    var fin_seq: UInt = 0u,
    var fin_acked: Boolean = false,
    var time_wait_time_ms: Long = 0L,
    // retransmission timers: https://www.rfc-editor.org/rfc/rfc6298.txt
    var srtt: Double = 0.0, // smoothed round-trip time
    var rttvar: Double = 0.0, // round-trip time variation
    // (2.1) Until a round-trip time (RTT) measurement has been made for a
    //         segment sent between the sender and receiver, the sender SHOULD
    //         set RTO <- 1 second, though the "backing off" on repeated
    //         retransmission discussed in (5.5) still applies.
    var rto: Double = 1.0, // retransmission timeout
    // https://www.rfc-editor.org/rfc/rfc2581
    // congestion window
    var iw: Int = 0,
    var ssthresh: Int = DEFAULT_WINDOW_SIZE.toInt(),
    var cwnd: Int = 0,
    var rwnd: Int = 0, // this should be the same thing as the remote sides window that is advertised out
    var congestionState: TcpCongestionState = TcpCongestionState.SLOW_START,
    // SACK
    var sack_permitted: Boolean = false,
    // last acceptable packets timestamp
    var last_timestamp: TcpOptionTimestamp? = null,
) {
    /**
     * Returns the difference between snd_una and snd_next while accounting for wraparound
     */
    fun outstandingBytes(): UInt =
        if (snd_nxt >= snd_una.value) {
            snd_nxt - snd_una.value
        } else {
            (UInt.MAX_VALUE - snd_una.value) + snd_nxt
        }
}
