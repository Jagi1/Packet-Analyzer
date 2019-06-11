package analizator

import java.io.File
import java.io.PrintWriter

/**
 * This method decode [header] of ARP protocol and sends back it decoded to client with [PrintWriter].
 *
 * ARP header structure:
 *   Hardware type ------ 2 bytes - header range 0...3
 *   Protocol type ------ 2 bytes - header range 4...7
 *   Hardware size ------ 1 bytes - header range 8...9
 *   Protocol size ------ 1 bytes - header range 10...11
 *   Operation code ----- 2 bytes - header range 12...15
 *   Sender MAC address - (value from Hardware size) bytes - header range ??
 *   Sender IP address -- (value from Protocol size) bytes - header range ??
 *   Target MAC address - 6 bytes - header range ??
 *   Target IP address -- 4 bytes - header range ??
 *
 * */

fun analyzeARP(pw: PrintWriter, header: String): Int {
    var response = "Analyzed ARP header:\n"
    val hType = header.substring(0, 4).toInt(16)
    var pType = "0x" + header.substring(4, 8)
    pType = when (pType) {
        "0x0800" -> "IPv4"
        "0x86dd" -> "IPv6"
        "0x0806" -> "ARP"
        else -> ""
    }
    val hSize = header.substring(8, 10).toInt(16)
    val pSize = header.substring(10, 12).toInt(16)
    val opCode = header.substring(12, 16).toInt(16)
    val shaBytesRange = 16 + hSize*2
    val sha = header.substring(16, shaBytesRange).chunked(2).joinToString(separator = ":")
    val spaBytesRange = shaBytesRange + pSize*2
    val spa = header.substring(shaBytesRange, spaBytesRange).chunked(2).map { it.toInt(16) }.joinToString(separator = ".")
    val thaBytesRange = spaBytesRange + 12
    val tha = header.substring(spaBytesRange, thaBytesRange).chunked(2).joinToString(separator = ":")
    val tpaBytesRange = thaBytesRange + 8
    val tpa = header.substring(thaBytesRange, tpaBytesRange).chunked(2).map { it.toInt(16) }.joinToString(separator = ".")

    response += "    Hardware type: $hType\n"
    response += "    Protocol type: $pType\n"
    response += "    Hardware size: $hSize\n"
    response += "    Protocol size: $pSize\n"
    response += "    Operation code: $opCode\n"
    response += "    Sender MAC address: $sha\n"
    response += "    Sender IP address: $spa\n"
    response += "    Target MAC address: $tha\n"
    response += "    Target IP address: $tpa\n"
    pw.println(response)
    File("$projectPath\\src\\logs\\HeadersSent.txt").run {
        appendText("ARP: $header\n$response\n", Charsets.UTF_8)
    }
    return 1
}
