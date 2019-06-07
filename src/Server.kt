package analizator

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.ServerSocket

/**
 * After establishing connection with client, packet is received with [BufferedReader].
 * First decoded header is EthernetII in [analyzeEthernetII] method. This method return type of next header
 * which is decoded with another method. Same process is repeated until all headers have been decoded.
 * */
fun main() = ServerSocket(11000).run {
    accept().let { socket ->
        // Create two-way communication (pw for sending and br for reading)
        val pw = PrintWriter(socket.getOutputStream(), true)
        val br = BufferedReader(InputStreamReader(socket.getInputStream()))
        // Packet to decode
        val packet: String? = br.readLine().replace(" ", "")
        // Decode header and get next protocol (if exists)
        val layer3Protocol = analyzeEthernetII(pw, packet!!.substring(0, 28))
        // Decide which protocol should be decoded next
        when (layer3Protocol) {
            "ipv4" -> {
                // Decode header and get next protocol (if exists)
                val layer4Protocol = analyzeIPV4(pw, packet.substring(28, 68))
                // Decide which protocol should be decoded next
                when (layer4Protocol) {
                    "tcp" -> analyzeTCP(pw, packet.substring(68, 108))
                    "udp" -> analyzeUDP(pw, packet.substring(68, 84))
                }
            }
            "ipv6" -> {
                // Decode header and get next protocol (if exists)
                val layer4Protocol = analyzeIPV6(pw, packet.substring(28, 108))
                // Decide which protocol should be decoded next
//                when (layer4Protocol) {
//                    "icmpv6" -> analyzeICMPV6(pw, datagram.substring(68, ?))
//                }
            }
//            "arp" -> analyzeARP(pw, datagram.substring(28, ?))
        }
        // Closing connection
        pw.close()
        br.close()
        socket.close()
    }
}