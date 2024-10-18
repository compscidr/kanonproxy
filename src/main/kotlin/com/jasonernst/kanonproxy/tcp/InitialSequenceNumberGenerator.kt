package com.jasonernst.kanonproxy.tcp

/**
 * See: https://www.rfc-editor.org/rfc/rfc9293.txt section 3.4.1
 *
 * To avoid confusion, we must prevent segments from one incarnation of
 *    a connection from being used while the same sequence numbers may
 *    still be present in the network from an earlier incarnation.  We want
 *    to assure this even if a TCP endpoint loses all knowledge of the
 *    sequence numbers it has been using.  When new connections are
 *    created, an initial sequence number (ISN) generator is employed that
 *    selects a new 32-bit ISN.  There are security issues that result if
 *    an off-path attacker is able to predict or guess ISN values [42].
 *
 *    TCP initial sequence numbers are generated from a number sequence
 *    that monotonically increases until it wraps, known loosely as a
 *    "clock".  This clock is a 32-bit counter that typically increments at
 *    least once every roughly 4 microseconds, although it is neither
 *    assumed to be realtime nor precise, and need not persist across
 *    reboots.  The clock component is intended to ensure that with a
 *    Maximum Segment Lifetime (MSL), generated ISNs will be unique since
 *    it cycles approximately every 4.55 hours, which is much longer than
 *    the MSL.  Please note that for modern networks that support high data
 *    rates where the connection might start and quickly advance sequence
 *    numbers to overlap within the MSL, it is recommended to implement the
 *    Timestamp Option as mentioned later in Section 3.4.3.
 *
 *    A TCP implementation MUST use the above type of "clock" for clock-
 *    driven selection of initial sequence numbers (MUST-8), and SHOULD
 *    generate its initial sequence numbers with the expression:
 *
 *    ISN = M + F(localip, localport, remoteip, remoteport, secretkey)
 *
 *    where M is the 4 microsecond timer, and F() is a pseudorandom
 *    function (PRF) of the connection's identifying parameters ("localip,
 *    localport, remoteip, remoteport") and a secret key ("secretkey")
 *    (SHLD-1).  F() MUST NOT be computable from the outside (MUST-9), or
 *    an attacker could still guess at sequence numbers from the ISN used
 *    for some other connection.  The PRF could be implemented as a
 *    cryptographic hash of the concatenation of the TCP connection
 *    parameters and some secret data.  For discussion of the selection of
 *    a specific hash algorithm and management of the secret key data,
 *    please see Section 3 of [42].
 *
 *    For each connection there is a send sequence number and a receive
 *    sequence number.  The initial send sequence number (ISS) is chosen by
 *    the data sending TCP peer, and the initial receive sequence number
 *    (IRS) is learned during the connection-establishing procedure.
 *
 *    For a connection to be established or initialized, the two TCP peers
 *    must synchronize on each other's initial sequence numbers.  This is
 *    done in an exchange of connection-establishing segments carrying a
 *    control bit called "SYN" (for synchronize) and the initial sequence
 *    numbers.  As a shorthand, segments carrying the SYN bit are also
 *    called "SYNs".  Hence, the solution requires a suitable mechanism for
 *    picking an initial sequence number and a slightly involved handshake
 *    to exchange the ISNs.
 *
 *    The synchronization requires each side to send its own initial
 *    sequence number and to receive a confirmation of it in acknowledgment
 *    from the remote TCP peer.  Each side must also receive the remote
 *    peer's initial sequence number and send a confirming acknowledgment.
 *
 *        1) A --> B  SYN my sequence number is X
 *        2) A <-- B  ACK your sequence number is X
 *        3) A <-- B  SYN my sequence number is Y
 *        4) A --> B  ACK your sequence number is Y
 *
 *    Because steps 2 and 3 can be combined in a single message this is
 *    called the three-way (or three message) handshake (3WHS).
 *
 *    A 3WHS is necessary because sequence numbers are not tied to a global
 *    clock in the network, and TCP implementations may have different
 *    mechanisms for picking the ISNs.  The receiver of the first SYN has
 *    no way of knowing whether the segment was an old one or not, unless
 *    it remembers the last sequence number used on the connection (which
 *    is not always possible), and so it must ask the sender to verify this
 *    SYN.  The three-way handshake and the advantages of a clock-driven
 *    scheme for ISN selection are discussed in [69].
 *
 *    From 3.4.2:
 *    To summarize: every segment emitted occupies one or more sequence
 *    numbers in the sequence space, and the numbers occupied by a segment
 *    are "busy" or "in use" until MSL seconds have passed.  Upon
 *    rebooting, a block of space-time is occupied by the octets and SYN or
 *    FIN flags of any potentially still in-flight segments.  If a new
 *    connection is started too soon and uses any of the sequence numbers
 *    in the space-time footprint of those potentially still in-flight
 *    segments of the previous connection incarnation, there is a potential
 *    sequence number overlap area that could cause confusion at the
 *    receiver.
 *
 *    High-performance cases will have shorter cycle times than those in
 *    the megabits per second that the base TCP design described above
 *    considers.  At 1 Gbps, the cycle time is 34 seconds, only 3 seconds
 *    at 10 Gbps, and around a third of a second at 100 Gbps.  In these
 *    higher-performance cases, TCP Timestamp Options and Protection
 *    Against Wrapped Sequences (PAWS) [47] provide the needed capability
 *    to detect and discard old duplicates.
 *
 *
 *    See also RFC 6528: https://www.rfc-editor.org/rfc/rfc6528.txt, section 3
 */
object InitialSequenceNumberGenerator {
    private val initialTime = System.currentTimeMillis() // used to determine the counter M which increases every 4 microseconds

    // every time bump starts up we will have a fresh "secret"
    private val secretKey = "initialSecret$initialTime" // secret key used to generate the initial sequence number

    fun generateInitialSequenceNumber(
        localIp: String,
        localPort: Int,
        remoteIp: String,
        remotePort: Int,
    ): UInt {
        val m = (System.currentTimeMillis() - initialTime) * 250 // 4 microseconds = 1/250 milliseconds
        val f = localIp + localPort + remoteIp + remotePort + secretKey

        // we may want to use a better hash function than whatever is provided by the JVM string hash
        // the RFC suggests MD5
        return m.toUInt() + f.hashCode().toUInt()
    }
}
