package analizator

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.Socket

fun main() = Socket("localhost", 11000).run {
    val pw = PrintWriter(getOutputStream(), true)
    val br = BufferedReader(InputStreamReader(getInputStream()))
    pw.println(datagram)
//    pw.println(ethernetII)
//    pw.println(datagramIPV4)
//    pw.println(datagramTCP)
    var datagramReceived1: String? = ""
    var datagramReceived2: String? = ""
    var line: String? = br.readLine()
    // First header
    while (line != null) {
        datagramReceived1 += line
        System.out.println(line)
        line = br.readLine()
    }
    System.out.println("\n")
    line = br.readLine()
    while (line != null) {
        datagramReceived2 += line
        System.out.println(line)
        line = br.readLine()
    }
    pw.close()
    br.close()
    close()
}