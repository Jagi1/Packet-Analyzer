package analizator

import java.io.PrintWriter

fun analyzeUDP(pw: PrintWriter, datagram: String): Int {
    var response = "Analyzed UDP header:\n"
    val sPort = "${datagram[0]}${datagram[1]}${datagram[2]}${datagram[3]}".toInt(16)
    val dPort = "${datagram[4]}${datagram[5]}${datagram[6]}${datagram[7]}".toInt(16)
    val length = "${datagram[8]}${datagram[9]}${datagram[10]}${datagram[11]}".toInt(16)
    val checkSum = "0x${datagram[12]}${datagram[13]}${datagram[14]}${datagram[15]}"
    response += "    Source port: $sPort\n"
    response += "    Destination port: $dPort\n"
    response += "    Length: $length\n"
    response += "    Checksum: $checkSum\n"
    pw.println(response)
    return length
}