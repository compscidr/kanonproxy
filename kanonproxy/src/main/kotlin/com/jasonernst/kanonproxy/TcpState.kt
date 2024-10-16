package com.jasonernst.kanonproxy

/**
 * See page 21, series of states for connection lifetime:
 *
 * https://datatracker.ietf.org/doc/html/rfc793#section-3.2
 */
enum class TcpState {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    TIME_WAIT,
    LAST_ACK,
}
