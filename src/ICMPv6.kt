package analizator

import java.io.File
import java.io.PrintWriter

/**
 * This method decode [header] of ICMPv6 protocol and sends back it decoded to client with [PrintWriter].
 *
 * ICMPv6 header structure:
 *   Type ------ 1 bytes - header range 0...1
 *   Code ------ 1 bytes - header range 2...3
 *   Checksum ------ 2 bytes - header range 4...7
 *   Rest of Header ------ 4 bytes - header range 8...15
 *   Data ----- (max 576 bytes) - header range 16...
 *
 * */

fun analyzeICMPv6(pw: PrintWriter, header: String): Int {
    var response = "Analyzed ICMPv6 header:\n"
    val type = header.substring(0, 2).toInt(16)
    val code = header.substring(2, 4).toInt(16)
    val checksum = "0x" + header.substring(4, 8)
    var rest = header.substring(8, 16)
    var data = header.substring(16)
    var nameType = ""

    when (type) {
        128 -> {
            nameType = "Echo (ping) request"
            rest = "Identifier: 0x${rest.substring(0, 4)}\n" +
                    "    Sequence: ${rest.substring(4, 8).toInt(16)}"
        }
        129 -> {
            nameType = "Echo (ping) reply"
            rest = "Identifier: 0x${rest.substring(0, 4)}\n" +
                    "    Sequence: ${rest.substring(4, 8).toInt(16)}"
        }
        135 -> {
            nameType = "Neighbor Solicitation"
            rest = "Reserved: $rest"
            data = "Data: ${data.substring(0,data.length-16)}\n" +
                    "    ICMPv6 Options:\n" +
                    "        Type: ${data.substring(data.length-16, data.length-14).toInt(16)}\n" +
                    "        Length: ${data.substring(data.length-14, data.length-12).toInt(16)}\n" +
                    "        Link-layer address: ${data.substring(data.length-12).chunked(2).joinToString(separator = ":")}"
        }
        136 -> {
            nameType = "Neighbor Advertisement"
            rest = "Flags: 0x$rest"
            data = "Data: ${data.substring(0,data.length-16)}\n" +
                    "    ICMPv6 Options:\n" +
                    "        Type: ${data.substring(data.length-16, data.length-14).toInt(16)}\n" +
                    "        Length: ${data.substring(data.length-14, data.length-12).toInt(16)}\n" +
                    "        Link-layer address: ${data.substring(data.length-12).chunked(2).joinToString(separator = ":")}"
        }
        else -> {
            rest = "Rest of Header: $rest"
            data = "Data: $data"
        }
    }
    response += "    Type: $type $nameType\n"
    response += "    Code: $code\n"
    response += "    Checksum: $checksum\n"
    response += "    $rest\n"
    response += "    $data\n"
    pw.println(response)
    logDecoding(header, response)
    return 1
}

