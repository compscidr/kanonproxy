package com.jasonernst.kanonproxy

import android.os.ParcelFileDescriptor
import android.os.ParcelFileDescriptor.AutoCloseInputStream
import android.os.ParcelFileDescriptor.AutoCloseOutputStream
import java.net.InetSocketAddress

class AndroidClient(
    socketAddress: InetSocketAddress = InetSocketAddress("127.0.0.1", 8080),
    private val vpnFileDescriptor: ParcelFileDescriptor
) : Client(socketAddress) {

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