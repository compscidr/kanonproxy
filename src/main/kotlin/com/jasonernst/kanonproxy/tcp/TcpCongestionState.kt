package com.jasonernst.kanonproxy.tcp

enum class TCPCongestionState {
    SLOW_START,
    CONGESTION_AVOIDANCE,
    FAST_RECOVERY,
    FAST_RETRANSMIT,
    TIME_OUT,
    UNKNOWN,
}
