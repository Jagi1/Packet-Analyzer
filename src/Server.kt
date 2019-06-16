package analizator

import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.ServerSocket
import java.nio.charset.Charset
import java.time.LocalDateTime

/**
 * After establishing connection with client, packet is received with [BufferedReader].
 * First decoded header is EthernetII in [analyzeEthernetII] method. This method return type of next header
 * which is decoded with another method. Same process is repeated until all headers have been decoded.
 * */
fun main() = ServerSocket(1057).run {
    while (true) {
        accept()?.let { socket ->
            // Create task that will be handled by another thread
            GlobalScope.launch {
                logConnection(socket)
                // Create two-way communication (pw for sending and br for reading)
                val pw = PrintWriter(socket.getOutputStream(), true)
                val br = BufferedReader(InputStreamReader(socket.getInputStream()))
                val protocolVersion = br.readLine().split(":").last()
                when (checkProtocolVersion(protocolVersion)) {
                    true -> pw.println("PDP:20")
                    else -> pw.println("PDP:30").also {
                        pw.close()
                        br.close()
                        close()
                        return@launch
                    }
                }
                // Packet to decode
                var packet: String? = br.readLine().replace(" ", "")
                // Convert packet from bin to hex if necessary
                if (checkBinOrHex(packet!!) == 1) {
                    packet = convertPacketBinToHex(packet).replace(", ", "")
                }
                logPacketReceived(socket, packet)
                // Decode header and get next protocol (if exists)
                val layer3Protocol = analyzeEthernetII(pw, packet.substring(0, 28))
                // Decide which protocol should be decoded next
                when (layer3Protocol) {
                    "ipv4" -> {
                        when (analyzeIPV4(pw, packet.substring(28, 68))) {
                            "tcp" -> analyzeTCP(pw, packet.substring(68, 108))
                            "udp" -> analyzeUDP(pw, packet.substring(68, 84))
                        }
                    }
                    "ipv6" -> {
                        val layer4Protocol = analyzeIPV6(pw, packet.substring(28, 108))
//                when (layer4Protocol) {
//                    "icmpv6" -> analyzeICMPV6(pw, datagram.substring(68, ?))
//                }
                    }
                    "arp" -> analyzeARP(pw, packet.substring(28, 120))
                }
                // Closing connection
                pw.println("PDP:END")
                pw.close()
                br.close()
                socket.close()
            }
        }
    }
}