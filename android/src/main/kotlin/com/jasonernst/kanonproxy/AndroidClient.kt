package com.jasonernst.kanonproxy

import android.os.ParcelFileDescriptor
import android.os.ParcelFileDescriptor.AutoCloseInputStream
import android.os.ParcelFileDescriptor.AutoCloseOutputStream
import com.jasonernst.packetdumper.AbstractPacketDumper
import com.jasonernst.packetdumper.DummyPacketDumper
import java.net.InetAddress
import java.nio.channels.DatagramChannel

class AndroidClient(
    datagramChannel: DatagramChannel,
    packetDumper: AbstractPacketDumper = DummyPacketDumper,
    vpnFileDescriptor: ParcelFileDescriptor,
    onlyDestinations: List<InetAddress> = emptyList(),
    onlyProtocols: List<UByte> = emptyList()
) : ProxyClient(datagramChannel, packetDumper, onlyDestinations, onlyProtocols) {

    private val inputStream = AutoCloseInputStream(vpnFileDescriptor)
    private val outputStream = AutoCloseOutputStream(vpnFileDescriptor)

    override fun tunRead(readBytes: ByteArray, bytesToRead: Int): Int {
        return inputStream.read(readBytes, 0, bytesToRead)
    }

    override fun tunWrite(writeBytes: ByteArray) {
        outputStream.write(writeBytes)
        outputStream.flush()
    }
}