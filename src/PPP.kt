package analizator

import java.io.PrintWriter

/**
 * This method decode [header] of PPP protocol and sends back it decoded to client with [PrintWriter].
 *
 * PPP header structure:
 *   Flags: ---------- 1 byte
 *      Version: ----- 4 bits
 *      Type: -------- 4 bits
 *   Code: ----------- 1 byte
 *   Session ID: ----- 2 bytes
 *   Payload length: - 2 bytes
 *   Protocol: ------- 2 bytes
 * */
fun analyzePPP(pw: PrintWriter, header: String): String {
    var flags = hexToByteString(header.substring(0, 2))
    val protocolID = header.substring(12)
    val protocol = when (protocolID) {
        "0021" -> "ipv4"
        "0057" -> "ipv6"
        else -> ""
    }
    var response = "Analyzed Point-to-Point Protocol header:\n" +
            "    Flags:\n" +
            "       Version: ${flags.substring(0, 4).toInt(2)}\n" +
            "       Type: ${flags.substring(4, 8).toInt(2)}\n" +
            "    Code: 0x${header.substring(2, 4)}\n" +
            "    Session ID: 0x${header.substring(4, 8)}\n" +
            "    Payload: ${header.substring(8, 12).toInt(16)}\n" +
            "    Protocol: 0x$protocolID ($protocol)"
    pw.println(response)
    logDecoding(header, response)
    return protocol
}