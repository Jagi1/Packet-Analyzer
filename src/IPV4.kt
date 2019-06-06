package analizator

import java.io.PrintWriter

fun analyzeIPV4(pw: PrintWriter, datagram: String): String {
    var response = "Analyzed IPv4 header:\n"
    val version = "${datagram[0]}".toInt(16)
    val ihl = "${datagram[1]}".toInt(16)
    val length = "${datagram[4]}${datagram[5]}${datagram[6]}${datagram[7]}".toInt(16)
    val id = "${datagram[8]}${datagram[9]}${datagram[10]}${datagram[11]}".toInt(16)
    val flags = hexToBytes("${datagram[12]}")
    val fOffset = "${hexToBytes("${datagram[12]}")[3]} ${hexToBytes("${datagram[13]}")} ${hexToBytes("${datagram[14]}")} ${hexToBytes("${datagram[15]}")}"
    val ttl = "${bytesToDouble("${hexToBytes("${datagram[16]}")}${hexToBytes("${datagram[17]}")}")}"
    val protocol = "${bytesToDouble("${hexToBytes("${datagram[18]}")}${hexToBytes("${datagram[19]}")}")}"
    val headerChecksum = "${datagram[20]}${datagram[21]}${datagram[22]}${datagram[23]}"
    val source = "${"${datagram[24]}${datagram[25]}".toInt(16)}.${"${datagram[26]}${datagram[27]}".toInt(16)}.${"${datagram[28]}${datagram[29]}".toInt(16)}.${"${datagram[30]}${datagram[31]}".toInt(16)}"
    val destination = "${"${datagram[32]}${datagram[33]}".toInt(16)}.${"${datagram[34]}${datagram[35]}".toInt(16)}.${"${datagram[36]}${datagram[37]}".toInt(16)}.${"${datagram[38]}${datagram[39]}".toInt(16)}"
    response += "    Version: $version\n"
    response += "    IHL: $ihl\n"
    response += "    Total length: $length\n"
    response += "    Identification: $id\n"
    response += "    Flags:\n"
    response += when {
        "${flags[0]}" == "0" -> "    ${flags[0]}... .... .... .... = Reserved bit: Not set\n"
        else -> "    ${flags[0]}... .... .... .... = Reserved bit: Set\n"
    }
    response += when {
        "${flags[1]}" == "0" -> "    .${flags[1]}.. .... .... .... = Don't fragment: Not set\n"
        else -> "    .${flags[1]}.. .... .... .... = Don't fragment: Set\n"
    }
    response += when {
        "${flags[2]}" == "0" -> "    ..${flags[2]}. .... .... .... = More fragments: Not set\n"
        else -> "    ..${flags[2]}. .... .... .... = More fragments: Set\n"
    }
    response += "    ...$fOffset = Fragment offset: 0\n"
    response += "    Time to live: $ttl\n"
    when (protocol) {
        "6" -> response += "    Protocol: TCP ($protocol)\n"
        "17" -> response += "    Protocol: UDP ($protocol)\n"
    }
    response += "    Header checksum: 0x$headerChecksum\n"
    response += "    Source: $source\n"
    response += "    Destination: $destination\n"
    pw.println(response)
    return when (protocol) {
        "17" -> "udp"
        "6" -> "tcp"
        else -> ""
    }
}