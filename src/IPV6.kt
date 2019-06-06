package analizator

import java.io.PrintWriter

fun analyzeIPV6(pw: PrintWriter, datagram: String): String {
    var response = "Analyzed IPv6 header:\n"
    val version = "    ${hexToBytes("${datagram[0]}")} .... = Version ${"${datagram[0]}".toInt(16)}\n"
    val trafficClass = "    .... ${hexToBytes("${datagram[1]}")} ${hexToBytes("${datagram[2]}")} .... .... .... .... .... = Traffic Class 0x${datagram[1]}${datagram[2]}\n"
    val differentiatedServices = "    .... ${hexToBytes("${datagram[1]}")} ${hexToBytes("${datagram[2]}").substring(0, 2)}.. .... .... .... .... .... = Differentiated Services Codepoint: ${"${hexToBytes("${datagram[1]}")}${hexToBytes("${datagram[2]}").substring(0, 1)}".toInt(16)}\n"
    val congestionNotification = "    .... .... ..${hexToBytes("${datagram[2]}").substring(2, 4)} .... .... .... .... .... = Explicit Congestion Notification: ${hexToBytes("${datagram[2]}").substring(2, 3).toInt()}\n"
    val flowLabel = "    .... .... .... ${hexToBytes("${datagram[3]}")} ${hexToBytes("${datagram[4]}")} ${hexToBytes("${datagram[5]}")} ${hexToBytes("${datagram[6]}")} ${hexToBytes("${datagram[7]}")} = Flow Label: 0x${datagram[3]}${datagram[4]}${datagram[5]}${datagram[6]}${datagram[7]}\n"
    val payloadLength = "    Payload Length: ${"${datagram[8]}${datagram[9]}${datagram[10]}${datagram[11]}".toInt(16)}\n"
    val nextHeader = "    Next header: ${"${datagram[12]}${datagram[13]}".toInt(16)}\n"
    val hopLimit = "    Hop limit: ${"${datagram[14]}${datagram[15]}".toInt(16)}\n"
    val source = "    Source: ${datagram[16]}${datagram[17]}${datagram[18]}${datagram[19]}:${datagram[20]}${datagram[21]}${datagram[22]}${datagram[23]}:${datagram[24]}${datagram[25]}${datagram[26]}${datagram[27]}" +
            ":${datagram[28]}${datagram[29]}${datagram[30]}${datagram[31]}:${datagram[32]}${datagram[33]}${datagram[34]}${datagram[35]}:${datagram[36]}${datagram[37]}${datagram[38]}${datagram[39]}" +
            ":${datagram[40]}${datagram[41]}${datagram[42]}${datagram[43]}:${datagram[44]}${datagram[45]}${datagram[46]}${datagram[47]}\n"
    val destination = "    Destination: ${datagram[48]}${datagram[49]}${datagram[50]}${datagram[51]}:${datagram[52]}${datagram[53]}${datagram[54]}${datagram[55]}:${datagram[56]}${datagram[57]}${datagram[58]}${datagram[59]}" +
            ":${datagram[60]}${datagram[61]}${datagram[62]}${datagram[63]}:${datagram[64]}${datagram[65]}${datagram[66]}${datagram[67]}:${datagram[68]}${datagram[69]}${datagram[70]}${datagram[71]}" +
            ":${datagram[72]}${datagram[73]}${datagram[74]}${datagram[75]}:${datagram[76]}${datagram[77]}${datagram[78]}${datagram[79]}\n"
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
    return when ("${datagram[12]}${datagram[13]}") {
        "3a" -> "icmpv6"
        else -> ""
    }
}