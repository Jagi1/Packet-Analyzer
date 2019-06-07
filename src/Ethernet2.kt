package analizator

import java.io.PrintWriter

/**
 * This method decode [header] of EthernetII protocol and sends back it decoded to client with [PrintWriter].
 *
 * EthernetII header structure:
 *   Destination MAC - 6 bytes - header range 0...11
 *   Source MAC ------ 6 bytes - header range 12..23
 *   EtherType ------- 2 bytes - header range 24..27
 * */
fun analyzeEthernetII(pw: PrintWriter, header: String): String {
    var response = "Analyzed EthernetII header:\n"
    val dAddress = "${header[0]}${header[1]}:${header[2]}${header[3]}:${header[4]}${header[5]}${header[6]}${header[7]}:${header[8]}${header[9]}:${header[10]}${header[11]}"
    val sAddress = "${header[12]}${header[13]}:${header[14]}${header[15]}:${header[16]}${header[17]}${header[18]}${header[19]}:${header[20]}${header[21]}:${header[22]}${header[23]}"
    val etherType = "0x${header[24]}${header[25]}${header[26]}${header[27]}"
    response += "    Destination address: $dAddress\n"
    response += "    Source address: $sAddress\n"
    response += "    EtherType: $etherType\n"
    pw.println(response)
    return when (etherType) {
        "0x0800" -> "ipv4"
        "0x86dd" -> "ipv6"
        "0x0806" -> "arp"
        else -> ""
    }
}