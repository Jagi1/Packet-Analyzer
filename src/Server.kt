package analizator

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.ServerSocket

fun main() = ServerSocket(11000).run {
    accept().let { socket ->
        val pw = PrintWriter(socket.getOutputStream(), true)
        val br = BufferedReader(InputStreamReader(socket.getInputStream()))
        var datagram: String? = br.readLine().replace(" ", "")
        System.out.println("Analyzing EthernetII...")
        val nextProtocol = analyzeEthernet2(pw, datagram!!.substring(0, 28))
        System.out.println("Analyzing $nextProtocol")
        when (nextProtocol) {
            "ipv4" -> analyzeIPV4(pw, datagram.substring(28, 184))
            "ipv6" -> analyzeIPV6(pw, datagram.substring(28, 184))
        }
//        analyzeIPV4(pw, datagram)
//        analyzeTCP(pw, datagram)
        pw.close()
        br.close()
        socket.close()
    }
}