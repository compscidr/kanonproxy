package com.jasonernst.kanonproxy

import com.jasonernst.knet.Packet
import java.net.InetSocketAddress

data class OutgoingClientPacket(
    val address: InetSocketAddress,
    val packet: Packet,
)
