package analizator

import java.io.PrintWriter

/**
 * This method decode [header] of IPV6 protocol and sends back it decoded to client with [PrintWriter].
 *
 * IPV6 header structure:
 *   Version ----------------- 4 bits --- header range 0....0
 *   Traffic class ----------- 1 byte --- header range 1....1
 *   Differentiated Services - 6 bits --- header range 1....2
 *   Congestion notification - 2 bits --- header range 2....2
 *   Flow label -------------- 24 bits -- header range 3....7
 *   Payload length ---------- 2 bytes -- header range 8...11
 *   Next header ------------- 1 byte --- header range 12..13
 *   Hop limit --------------- 1 byte --- header range 14..15
 *   Source ------------------ 16 bytes - header range 16..47
 *   Destination ------------- 16 bytes - header range 48..79
 * */

fun analyzeIPV6(pw: PrintWriter, header: String): String {
    var response = "Analyzed IPv6 header:\n"
    val version = "    ${hexToBytes("${header[0]}")} .... = Version ${"${header[0]}".toInt(16)}\n"
    val trafficClass = "    .... ${hexToBytes("${header[1]}")} ${hexToBytes("${header[2]}")} .... .... .... .... .... = Traffic Class 0x${header[1]}${header[2]}\n"
    val differentiatedServices = "    .... ${hexToBytes("${header[1]}")} ${hexToBytes("${header[2]}").substring(0, 2)}.. .... .... .... .... .... = Differentiated Services Codepoint: ${"${hexToBytes("${header[1]}")}${hexToBytes("${header[2]}").substring(0, 1)}".toInt(16)}\n"
    val congestionNotification = hexToBytes("${header[2]}").substring(2, 4) + " .... .... .... .... .... = Explicit Congestion Notification: " + hexToBytes("${header[2]}").substring(2, 4).toInt()
    val flowLabel = header.substring(3, 8).chunked(1).map { hexToBytes(it) }.joinToString(separator = " ") + " = Flow Label: 0x" + header.substring(3, 8)
    val payloadLength = header.substring(8, 12).toInt(16)
    val nextHeader = header.substring(12, 14).toInt(16)
    val hopLimit = header.substring(14, 16).toInt(16)
    val source = header.substring(16, 48).chunked(2).joinToString(separator = ":")
    val destination = header.substring(48, 80).chunked(2).joinToString(separator = ":")
    response += version
    response += trafficClass
    response += differentiatedServices
    response += "    .... .... ..$congestionNotification\n"
    response += "    .... .... .... $flowLabel\n"
    response += "    Payload length: $payloadLength\n"
    response += "    Next header: $nextHeader\n"
    response += "    Hop limit: $hopLimit\n"
    response += "    Source: $source\n"
    response += "    Destination: $destination\n"
    pw.println(response)
    return when ("${header[12]}${header[13]}") {
        "3a" -> "icmpv6"
        else -> ""
    }
}