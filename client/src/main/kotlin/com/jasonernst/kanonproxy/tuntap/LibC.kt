package com.jasonernst.kanonproxy.tuntap

import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Platform
import com.sun.jna.Structure

object LibC {
    init {
        Native.register(Platform.C_LIBRARY_NAME)
    }

    external fun open(
        path: String,
        flags: Int,
    ): Int

    external fun ioctl(
        fd: Int,
        cmd: NativeLong,
        p: Structure,
    ): Int

    external fun close(fd: Int): Int
}
