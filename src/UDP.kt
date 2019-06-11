package analizator

import java.io.File
import java.io.PrintWriter

/**
 * This method decode [header] of UDP protocol and sends back it decoded to client with [PrintWriter].
 *
 * UDP header structure:
 *   Source port ------ 2 bytes - header range 0....3
 *   Destination port - 2 bytes - header range 4....7
 *   Length ----------- 2 bytes - header range 8...11
 *   Checksum --------- 2 bytes - header range 12..15
 * */

fun analyzeUDP(pw: PrintWriter, header: String): Int {
    var response = "Analyzed UDP header:\n"
    val sPort = "${header[0]}${header[1]}${header[2]}${header[3]}".toInt(16)
    val dPort = "${header[4]}${header[5]}${header[6]}${header[7]}".toInt(16)
    val length = "${header[8]}${header[9]}${header[10]}${header[11]}".toInt(16)
    val checkSum = "0x${header[12]}${header[13]}${header[14]}${header[15]}"
    response += "    Source port: $sPort\n"
    response += "    Destination port: $dPort\n"
    response += "    Length: $length\n"
    response += "    Checksum: $checkSum\n"
    pw.println(response)
    File("$projectPath\\src\\logs\\HeadersSent.txt").run {
        appendText("UDP: $header\n$response\n", Charsets.UTF_8)
    }
    return length
}