package com.jasonernst.kanonproxy

import com.jasonernst.knet.Packet

data class RetransmittablePacket(
    val packet: Packet,
    val lastSent: Long,
    val timeout: Long,
)
