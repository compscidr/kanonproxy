package com.jasonernst.kanonproxy.tuntap

import com.sun.jna.Native
import com.sun.jna.Structure
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets

@Structure.FieldOrder("name", "flags", "padding")
class IfReq(
    @JvmField var flags: Short = 0,
    nameString: String = "",
) : Structure() {
    companion object {
        // from if.h - the max length of an interface name
        const val IF_NAME_LENGTH: Int = 16
        const val IF_REQ_LENGTH: Int = 40
    }

    private val logger = LoggerFactory.getLogger(javaClass)

    @JvmField var name: ByteArray = ByteArray(IF_NAME_LENGTH)

    @JvmField var padding: ByteArray = ByteArray(IF_REQ_LENGTH - IF_NAME_LENGTH - 2)

    init {
        val nameBytes = nameString.toByteArray(StandardCharsets.US_ASCII)
        if (nameBytes.size > IF_NAME_LENGTH) {
            logger.warn("Interface name is too long, truncating to $IF_NAME_LENGTH characters")
            nameBytes.copyInto(this.name, 0, 0, IF_NAME_LENGTH)
        } else {
            nameBytes.copyInto(this.name, 0, 0, nameBytes.size)
        }
    }
    // there are actually other fields in here, but we don't need them to set this as a TAP
    // device, we just calling it "padding": https://github.com/spotify/linux/blob/master/include/linux/if.h#L172

    override fun toString(): String =
        "IfReq(name=${Native.toString(name, StandardCharsets.US_ASCII)}, flags=$flags, padding length=${padding.size})"
}
