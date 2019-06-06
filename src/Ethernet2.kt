package analizator

import java.io.PrintWriter

fun analyzeEthernet2(pw: PrintWriter, datagram: String): String {
    var response = "Analyzed EthernetII header:\n"
    val dAddress = "${datagram[0]}${datagram[1]}:${datagram[2]}${datagram[3]}:${datagram[4]}${datagram[5]}${datagram[6]}${datagram[7]}:${datagram[8]}${datagram[9]}:${datagram[10]}${datagram[11]}"
    val sAddress = "${datagram[12]}${datagram[13]}:${datagram[14]}${datagram[15]}:${datagram[16]}${datagram[17]}${datagram[18]}${datagram[19]}:${datagram[20]}${datagram[21]}:${datagram[22]}${datagram[23]}"
    val etherType = "0x${datagram[24]}${datagram[25]}${datagram[26]}${datagram[27]}"
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