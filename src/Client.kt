package analizator

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.Socket

/**
 * Client establish connection, send packet to decode with [PrintWriter] and receive
 * same decoded packet with [getResponse].
 * */
fun main() = Socket("localhost", 11000).run {
    // Create two-way communication (pw for sending and br for reading)
    val pw = PrintWriter(getOutputStream(), true)
    val br = BufferedReader(InputStreamReader(getInputStream()))
    // Send packet to decode
    pw.println(ethernetII_IPV4_TCP)
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
    while (line != null) {
        System.out.println(line)
        line = br.readLine()
    }
}