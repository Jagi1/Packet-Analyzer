package analizator

import java.io.File
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
    val version = header.substring(0, 1).toInt(16)
    val ihl = header.substring(1, 2).toInt(16)
    val length = header.substring(4, 8).toInt(16)
    val id = header.substring(8, 12).toInt(16)
    val flags = hexToBytes(header.substring(12 ,13))
    val fOffset = hexToBytes(header[12].toString())[3] + " " + header.substring(13, 16).chunked(1).map { it }.joinToString { hexToBytes(it) }
    val ttl = bytesToInt(hexToBytes(header[16].toString()) + hexToBytes(header[17].toString()))
    val protocol = bytesToInt(hexToBytes(header[18].toString()) + hexToBytes(header[19].toString())).toString()
    val headerChecksum = header.substring(20, 24)
    val source = header.substring(24, 32).chunked(2).map { it.toInt(16) }.joinToString(separator = ".")
    val destination = header.substring(32, 40).chunked(2).map { it.toInt(16) }.joinToString(separator = ".")
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
    File("$projectPath\\src\\logs\\HeadersSent.txt").run {
        appendText("IPV4: $header\n$response\n", Charsets.UTF_8)
    }
    return when (protocol) {
        "17" -> "udp"
        "6" -> "tcp"
        else -> ""
    }
}