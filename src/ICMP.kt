package analizator

import java.io.File
import java.io.PrintWriter

/**
 * This method decode [header] of ICMP protocol and sends back it decoded to client with [PrintWriter].
 *
 * ICMP header structure:
 *   Type ------ 1 bytes - header range 0...1
 *   Code ------ 1 bytes - header range 2...3
 *   Checksum ------ 2 bytes - header range 4...7
 *   Rest of Header ------ 4 bytes - header range 8...15
 *   Data ----- (max 576 bytes) - header range 16...
 *
 * */

fun analyzeICMP(pw: PrintWriter, header: String): Int {
    var response = "Analyzed ICMP header:\n"
    var type = header.substring(0, 2).toInt(16)
    val code = header.substring(2, 4).toInt(16)
    val checksum = "0x" + header.substring(4, 8)
    val rest = header.substring(8, 16)
    val data = header.substring(16, header.length)

    response += "    Type: $type\n"
    response += "    Code: $code\n"
    response += "    Checksum: $checksum\n"
    response += "    Rest of Header: $rest\n"
    response += "    Data: $data\n"
    pw.println(response)
    logDecoding(header, response)
    return 1
}

