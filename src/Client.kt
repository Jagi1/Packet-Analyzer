package analizator

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.Socket

/**
 * Client establish connection, send packet to decode with [PrintWriter] and receive
 * same decoded packet with [getResponse].
 * */
fun main() = Socket("localhost", 1057).run {
    // Create two-way communication (pw for sending and br for reading)
    val pw = PrintWriter(getOutputStream(), true)
    val br = BufferedReader(InputStreamReader(getInputStream()))
    // Init connection
    pw.println("PDP:INIT:1.0")
    // Get response code
    var responseCode = br.readLine().split(":").last()
    if (responseCode == "30") {
        pw.close()
        br.close()
        close()
        return@run
    }
    // Send packet type
    System.out.println("Specify packet type (icmp, icmpv6, l2tp, dns, dhcp, arp, rarp):")
    pw.println("PDP:${readLine()}")
    // Get response code
    responseCode = br.readLine().split(":").last()
    if (responseCode == "31") {
        System.out.println("Unsupported protocol. Ending communication...")
        pw.close()
        br.close()
        close()
        return@run
    }
    // Send packet to decode
    pw.println(ethernetII_IPv6_UDP_DNS)
    // Receive decoded packet
    getResponse(br)
    // Close connection
    pw.close()
    br.close()
    close()
}

/**
 * Gets decoded packet from server. Packet is read from [BufferedReader].
 * */
fun getResponse(br: BufferedReader) {
    var line: String? = br.readLine()
    var lastLine = ""
    while (line != null) {
        lastLine = line
        System.out.println(line)
        line = br.readLine()
    }
    when (lastLine){
        "PDP:31" -> {System.out.println("Unsupported protocol.")}
        "PDP:32" -> {System.out.println("Unexpected error.")}
    }
}