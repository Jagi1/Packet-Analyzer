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
    val congestionNotification = "    .... .... ..${hexToBytes("${header[2]}").substring(2, 4)} .... .... .... .... .... = Explicit Congestion Notification: ${hexToBytes("${header[2]}").substring(2, 4).toInt()}\n"
    val flowLabel = "    .... .... .... ${hexToBytes("${header[3]}")} ${hexToBytes("${header[4]}")} ${hexToBytes("${header[5]}")} ${hexToBytes("${header[6]}")} ${hexToBytes("${header[7]}")} = Flow Label: 0x${header[3]}${header[4]}${header[5]}${header[6]}${header[7]}\n"
    val payloadLength = "    Payload Length: ${"${header[8]}${header[9]}${header[10]}${header[11]}".toInt(16)}\n"
    val nextHeader = "    Next header: ${"${header[12]}${header[13]}".toInt(16)}\n"
    val hopLimit = "    Hop limit: ${"${header[14]}${header[15]}".toInt(16)}\n"
    val source = "    Source: ${header[16]}${header[17]}${header[18]}${header[19]}:${header[20]}${header[21]}${header[22]}${header[23]}:${header[24]}${header[25]}${header[26]}${header[27]}" +
            ":${header[28]}${header[29]}${header[30]}${header[31]}:${header[32]}${header[33]}${header[34]}${header[35]}:${header[36]}${header[37]}${header[38]}${header[39]}" +
            ":${header[40]}${header[41]}${header[42]}${header[43]}:${header[44]}${header[45]}${header[46]}${header[47]}\n"
    val destination = "    Destination: ${header[48]}${header[49]}${header[50]}${header[51]}:${header[52]}${header[53]}${header[54]}${header[55]}:${header[56]}${header[57]}${header[58]}${header[59]}" +
            ":${header[60]}${header[61]}${header[62]}${header[63]}:${header[64]}${header[65]}${header[66]}${header[67]}:${header[68]}${header[69]}${header[70]}${header[71]}" +
            ":${header[72]}${header[73]}${header[74]}${header[75]}:${header[76]}${header[77]}${header[78]}${header[79]}\n"
    response += version
    response += trafficClass
    response += differentiatedServices
    response += congestionNotification
    response += flowLabel
    response += payloadLength
    response += nextHeader
    response += hopLimit
    response += source
    response += destination
    pw.println(response)
    return when ("${header[12]}${header[13]}") {
        "3a" -> "icmpv6"
        else -> ""
    }
}