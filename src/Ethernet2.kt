package analizator

import java.io.File
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
    val dAddress = header.substring(0, 12).chunked(2).joinToString(separator = ":")
    val sAddress = header.substring(12, 24).chunked(2).joinToString(separator = ":")
    val etherTypeID = header.substring(24, 28)
    val etherType = when (etherTypeID) {
        "0800" -> "ipv4"
        "86dd" -> "ipv6"
        "0806" -> "arp"
        "8864" -> "ppp"
        else -> ""
    }
    response += "    Destination address: $dAddress\n"
    response += "    Source address: $sAddress\n"
    response += "    EtherType: 0x$etherTypeID ($etherType)\n"
    pw.println(response)
    logDecoding(header, response)
    return etherType
}