package analizator

import java.io.PrintWriter

/**
 * This method decode [header] of IPV6 protocol and sends back it decoded to client with [PrintWriter].
 *
 * IPV6 header structure:
 *   Version -------------------------------- 4 bits -- header range 0....0
 *   Internet header length (IHL) ----------- 4 bits -- header range 1....1
 *   Differentiated Services ---------------- 6 bits -- header range 1....2
 *   Explicit Congestion Notification (ECN) - 2 bits -- header range 2....2
 *   Total Length --------------------------- 2 bytes - header range 4....7
 *   Identification ------------------------- 2 bytes - header range 8...11
 *   Flags ---------------------------------- 3 bits -- header range 12..12
 *   Fragment Offset ------------------------ 13 bits - header range 13..15
 *   Time To Live (TTL) --------------------- 1 byte -- header range 16..17
 *   Protocol ------------------------------- 1 byte -- header range 18..19
 *   Header Checksum ------------------------ 2 bytes - header range 20..23
 *   Source address ------------------------- 4 bytes - header range 24..31
 *   Destination address -------------------- 4 bytes - header range 32..39
 * */

fun analyzeIPV4(pw: PrintWriter, header: String): String {
    var response = "Analyzed IPv4 header:\n"
    val version = "${header[0]}".toInt(16)
    val ihl = "${header[1]}".toInt(16)
    val length = "${header[4]}${header[5]}${header[6]}${header[7]}".toInt(16)
    val id = "${header[8]}${header[9]}${header[10]}${header[11]}".toInt(16)
    val flags = hexToBytes("${header[12]}")
    val fOffset = "${hexToBytes("${header[12]}")[3]} ${hexToBytes("${header[13]}")} ${hexToBytes("${header[14]}")} ${hexToBytes("${header[15]}")}"
    val ttl = "${bytesToInt("${hexToBytes("${header[16]}")}${hexToBytes("${header[17]}")}")}"
    val protocol = "${bytesToInt("${hexToBytes("${header[18]}")}${hexToBytes("${header[19]}")}")}"
    val headerChecksum = "${header[20]}${header[21]}${header[22]}${header[23]}"
    val source = "${"${header[24]}${header[25]}".toInt(16)}.${"${header[26]}${header[27]}".toInt(16)}.${"${header[28]}${header[29]}".toInt(16)}.${"${header[30]}${header[31]}".toInt(16)}"
    val destination = "${"${header[32]}${header[33]}".toInt(16)}.${"${header[34]}${header[35]}".toInt(16)}.${"${header[36]}${header[37]}".toInt(16)}.${"${header[38]}${header[39]}".toInt(16)}"
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