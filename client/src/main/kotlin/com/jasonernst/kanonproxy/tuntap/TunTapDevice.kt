package com.jasonernst.kanonproxy.tuntap

import com.sun.jna.Native
import com.sun.jna.NativeLong
import jnr.enxio.channels.NativeSocketChannel
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import kotlin.experimental.or

class TunTapDevice {
    companion object {
        // the function call for configuring a TUN interface in ioctl from if_tun.h
        private val TUN_SET_IFF = NativeLong(0x400454caL)
        private const val O_RDWR = 2 // from fcntl-linux.h
        private const val IFACE_NAME = "kanon"
        private const val DEVICE_TYPE: Short = 0x0001 // 0x0001 for TUN, 0x0002 for TAP

        // from if_tun.h - tells the kernel to not add packet information header before the packet
        private const val FLAGS_IFF_NO_PI: Short = 0x1000
    }

    private val logger = LoggerFactory.getLogger(javaClass)
    private lateinit var nativeSocketChannel: NativeSocketChannel

    fun open() {
        val fd = LibC.open("/dev/net/tun", O_RDWR)
        if (fd < 0) {
            throw RuntimeException("Error opening TUN/TAP device: $fd ${Native.getLastError()}")
        } else {
            logger.debug("Opened TUN/TAP device: $fd")
        }
        val tunConfigReq = IfReq(flags = (DEVICE_TYPE or FLAGS_IFF_NO_PI), nameString = IFACE_NAME)
        logger.debug("Creating TUN/TAP device: $tunConfigReq")

        // sets the device to a TUN or TAP device with no packet info
        val tunCreateResult = LibC.ioctl(fd, TUN_SET_IFF, tunConfigReq)
        if (tunCreateResult != 0) {
            LibC.close(fd)
            throw RuntimeException("Error creating TUN/TAP device: $tunCreateResult ${Native.getLastError()}")
        }
        logger.debug("Created TUN/TAP device")
        nativeSocketChannel = NativeSocketChannel(fd)
    }

    fun read(
        readBytes: ByteArray,
        bytesToRead: Int,
    ): Int {
        // why are we doing this and not using nativeSocketChannel read?
        // return LibC.read(nativeSocketChannel.fd, readBytes, NativeLong(bytesToRead.toLong()))
        val buffer = ByteBuffer.allocate(bytesToRead)
        val result = nativeSocketChannel.read(buffer)
        logger.debug("Read $result bytes from nativesocket")
        if (result > 0) {
            buffer.rewind()
            buffer.get(readBytes)
            buffer.clear()
        } else {
            logger.debug("Read $result bytes")
        }
        return result
    }

    fun write(writeBytes: ByteArray) {
        val writeBuffer = ByteBuffer.wrap(writeBytes)
        while (writeBuffer.hasRemaining()) {
            nativeSocketChannel.write(writeBuffer)
        }
    }

    fun close() {
        nativeSocketChannel.close()
    }
}
