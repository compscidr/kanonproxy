package com.jasonernst.kanonproxy.tcp

import com.jasonernst.knet.Packet

data class RetransmittablePacket(
    val packet: Packet,
    val lastSent: Long,
    val timeout: Long,
)
