package com.jasonernst.kanonproxy.tcp

enum class TcpCongestionState {
    SLOW_START,
    CONGESTION_AVOIDANCE,
    FAST_RECOVERY,
    FAST_RETRANSMIT,
    TIME_OUT,
    UNKNOWN,
}
