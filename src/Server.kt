package analizator

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.ServerSocket

fun main() = ServerSocket(11000).run {
    accept().let { socket ->
        val pw = PrintWriter(socket.getOutputStream(), true)
        val br = BufferedReader(InputStreamReader(socket.getInputStream()))
        val datagram: String? = br.readLine().replace(" ", "")
        val layer2Protocol = analyzeEthernet2(pw, datagram!!.substring(0, 28))
        when (layer2Protocol) {
            "ipv4" -> {
                System.out.println("IPV4")
                val layer3Protocol = analyzeIPV4(pw, datagram.substring(28, 68))
                when (layer3Protocol) {
                    "tcp" -> analyzeTCP(pw, datagram.substring(68, 108))
                    "udp" -> analyzeUDP(pw, datagram.substring(68, 84))
                }
            }
            "ipv6" -> {
                System.out.println("IPV6")
                val layer3Protocol = analyzeIPV6(pw, datagram.substring(28, 108))
                when (layer3Protocol) {
//                    "icmpv6" -> analyzeICMPV6(pw, datagram.substring(68, ?))
                }
            }
//            "arp" -> analyzeARP(pw, datagram.substring(28, ?))
        }
        pw.close()
        br.close()
        socket.close()
    }
}