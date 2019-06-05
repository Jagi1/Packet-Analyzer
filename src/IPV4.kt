package analizator

import java.io.PrintWriter

fun analyzeIPV4(pw: PrintWriter, datagram: String?) = datagram?.let {
    var response = "IPv4:\n"
    val version = "${it[0]}".toInt(16)
    val ihl = "${it[1]}".toInt(16)
    val length = "${it[4]}${it[5]}${it[6]}${it[7]}".toInt(16)
    val id = "${it[8]}${it[9]}${it[10]}${it[11]}".toInt(16)
    val flags = hexToBytes("${it[12]}")
    val fOffset = "${hexToBytes("${it[12]}")[3]} ${hexToBytes("${it[13]}")} ${hexToBytes("${it[14]}")} ${hexToBytes("${it[15]}")}"
    val ttl = "${bytesToDouble("${hexToBytes("${it[16]}")}${hexToBytes("${it[17]}")}")}"
    val protocol = "${bytesToDouble("${hexToBytes("${it[18]}")}${hexToBytes("${it[19]}")}")}"
    val headerChecksum = "${it[20]}${it[21]}${it[22]}${it[23]}"
    val source = "${"${it[24]}${it[25]}".toInt(16)}.${"${it[26]}${it[27]}".toInt(16)}.${"${it[28]}${it[29]}".toInt(16)}.${"${it[30]}${it[31]}".toInt(16)}"
    val destination = "${"${it[32]}${it[33]}".toInt(16)}.${"${it[34]}${it[35]}".toInt(16)}.${"${it[36]}${it[37]}".toInt(16)}.${"${it[38]}${it[39]}".toInt(16)}"
    response += "Version: $version\n"
    response += "IHL: $ihl\n"
    response += "Total length: $length\n"
    response += "Identification: $id\n"
    response += "Flags:\n"
    response += when {
        "${flags[0]}" == "0" -> " ${flags[0]}... .... .... .... = Reserved bit: Not set\n"
        else -> " ${flags[0]}... .... .... .... = Reserved bit: Set\n"
    }
    response += when {
        "${flags[1]}" == "0" -> " .${flags[1]}.. .... .... .... = Don't fragment: Not set\n"
        else -> " .${flags[1]}.. .... .... .... = Don't fragment: Set\n"
    }
    response += when {
        "${flags[2]}" == "0" -> " ..${flags[2]}. .... .... .... = More fragments: Not set\n"
        else -> " ..${flags[2]}. .... .... .... = More fragments: Set\n"
    }
    response += " ...$fOffset = Fragment offset: 0\n"
    response += "Time to live: $ttl\n"
    when (protocol) {
        "6" -> response += "Protocol: TCP ($protocol)\n"
        "17" -> response += "Protocol: UDP ($protocol)\n"
    }
    response += "Protocol: $protocol\n"
    response += "Header checksum: 0x$headerChecksum\n"
    response += "Source: $source\n"
    response += "Destination: $destination"
    pw.println(response)
}