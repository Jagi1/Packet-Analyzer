package analizator

import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.ServerSocket
import java.net.SocketException
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
                        socket.close()
                        return@launch
                    }
                }
                // Packet type
                var packetType = br.readLine().split(":").last().toLowerCase()
                when (checkPacketType(packetType.toLowerCase())) {
                    true -> pw.println("PDP:21")
                    else -> pw.println("PDP:31").also {
                        pw.close()
                        br.close()
                        socket.close()
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
                        ipv4(pw, packet.substring(28), packetType)
                    }
                    "ipv6" -> {
                        val layer4Protocol = analyzeIPV6(pw, packet.substring(28, 108))
                        when (layer4Protocol) {
                            "icmpv6" -> {
                                analyzeICMPv6(pw, packet.substring(108))
                            }
                            else -> analyze4Protocol(packetType, -1, pw, packet.substring(108))
                        }
                    }
                    "arp", "rarp" -> analyzeARP(pw, packet.substring(28, 120))
                    "ppp" -> {
                        when(analyzePPP(pw, packet.substring(28, 44))) {
                            "ipv4" -> {
                                ipv4(pw, packet.substring(44), packetType)
                            }
                        }
                    }
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

fun ipv4(pw: PrintWriter, packet: String, packetType: String){
    when (analyzeIPV4(pw, packet.substring(0, 40))) {
        "tcp" -> {
            analyzeTCP(pw, packet.substring(40, 80))
            analyze4Protocol(packetType, -1, pw, packet.substring(80))
        }
        "udp" -> {
            val length = analyzeUDP(pw, packet.substring(40, 56))
            analyze4Protocol(packetType, length, pw, packet.substring(56))
        }
        "icmp" -> {
            analyzeICMP(pw, packet.substring(40))
        }
    }
}