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
    val etherType = header.substring(24, 28)
    response += "    Destination address: $dAddress\n"
    response += "    Source address: $sAddress\n"
    response += "    EtherType: 0x$etherType\n"
    pw.println(response)
    File("$projectPath\\src\\logs\\HeadersSent.txt").run {
        appendText("EthernetII: $header\n$response\n", Charsets.UTF_8)
    }
    return when (etherType) {
        "0800" -> "ipv4"
        "86dd" -> "ipv6"
        "0806" -> "arp"
        else -> ""
    }
}