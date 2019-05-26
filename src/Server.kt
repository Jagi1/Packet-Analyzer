package analizator

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.ServerSocket
import kotlin.math.pow

fun main() = ServerSocket(11000).run {
    accept().let { socket ->
        val pw = PrintWriter(socket.getOutputStream(), true)
        val br = BufferedReader(InputStreamReader(socket.getInputStream()))
        var datagram: String? = br.readLine().replace(" ", "")
        analyzeIPV4(pw, datagram)
//        analyzeTCP(pw, datagram)
        pw.close()
        br.close()
        socket.close()
    }
}

private fun analyzeIPV4(pw: PrintWriter, datagram: String?) = datagram?.let {
    var response = ""
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

private fun analyzeTCP(pw: PrintWriter, datagram: String?) = datagram?.let {
    var response = ""
    System.out.println("Received datagram:\n$datagram\n")
    val sPort = "${it[0]}${it[1]}${it[2]}${it[3]}".toInt(16)
    val dPort = "${it[4]}${it[5]}${it[6]}${it[7]}".toInt(16)
    val seqNumber = "${it[8]}${it[9]}${it[10]}${it[11]}${it[12]}${it[13]}${it[14]}${it[15]}".toLong(16)
    val ackNumber = "${it[16]}${it[17]}${it[18]}${it[19]}${it[20]}${it[21]}${it[22]}${it[23]}".toLong(16)
    val offset = "${it[24]}".toInt(16)
    val reserved = arrayListOf(hexToBytes("${it[24]}")[0], hexToBytes("${it[24]}")[1], hexToBytes("${it[24]}")[2])
    val nonce = "${hexToBytes("${it[24]}")[3]}"
    val congestion = "${hexToBytes("${it[25]}")[0]}"
    val ecnEcho = "${hexToBytes("${it[25]}")[1]}"
    val urgent = "${hexToBytes("${it[25]}")[2]}"
    val acknowledgement = "${hexToBytes("${it[25]}")[3]}"
    val push = "${hexToBytes("${it[26]}")[0]}"
    val reset = "${hexToBytes("${it[26]}")[1]}"
    val syn = "${hexToBytes("${it[26]}")[2]}"
    val fin = "${hexToBytes("${it[26]}")[3]}"
    val windowSize = "${it[27]}${28}${29}${30}".toInt(16)
    val urgentPointer = "${it[35]}${it[36]}${it[37]}${it[38]}".toInt(16)
    response += "Source port: $sPort\n"
    response += "Destination port: $dPort\n"
    response += "Sequence number: $seqNumber\n"
    response += "Acknowledgment number: $ackNumber\n"
    response += "Offest: $offset\n"
    response += "Flags:\n"
    response += when {
        "${reserved[0]}${reserved[1]}${reserved[2]}" == "000" -> "${reserved[0]}${reserved[1]}${reserved[2]}. .... .... = Reserved: Not set\n"
        else -> "${reserved[0]}${reserved[1]}${reserved[2]}. .... .... = Reserved: Set\n"
    }
    response += when (nonce) {
        "0" -> "...$nonce .... .... = Nonce: Not set\n"
        else -> "...$nonce .... .... = Nonce: Set\n"
    }
    response += when (congestion) {
        "0" -> ".... $congestion... .... = Congestion Window Reduced (CWR): Not set\n"
        else -> ".... $congestion... .... = Congestion Window Reduced (CWR): Set\n"
    }
    response += when (ecnEcho) {
        "0" -> ".... .$ecnEcho.. .... = ECN-Echo: Not set\n"
        else -> ".... .$ecnEcho.. .... = ECN-Echo: Set\n"
    }
    response += when (urgent) {
        "0" -> ".... ..$urgent. .... = Urgent: Not set\n"
        else -> ".... ..$urgent. .... = Urgent: Set\n"
    }
    response += when (acknowledgement) {
        "0" -> ".... ...$acknowledgement .... = Acknowledgement: Not set\n"
        else -> ".... .... ...$acknowledgement = Acknowledgement: Set\n"
    }
    response += when (push) {
        "0" -> ".... .... $push... = Push: Not set\n"
        else -> ".... .... $push... = Push: Set\n"
    }
    response += when (reset) {
        "0" -> ".... .... .$reset.. = Reset: Not set\n"
        else -> ".... .... .$reset.. = Reset: Set\n"
    }
    response += when (syn) {
        "0" -> ".... .... ..$syn. = Syn: Not set\n"
        else -> ".... .... ..$syn. = Syn: Set\n"
    }
    response += when (fin) {
        "0" -> ".... .... ...$fin = Fin: Not set\n"
        else -> ".... .... ...$fin = Fin: Set\n"
    }
    response += "Window size value: $windowSize\n"
    response += "Checksum: 0x${it[31]}${it[32]}${it[33]}${it[34]}\n"
    response += "Urgent pointer: $urgentPointer\n"
    pw.println(response)
}

/**
 * It converts [bytes] into [Int] value.
 * Example: 00011100 = 8 + 16 + 32 = 56
 * */
private fun bytesToDouble(bytes: String): Int {
    var value = 0.0
    var iter = 0
    bytes.reversed().forEach {
        if (it.toString().toInt() == 1) {
            value += 2.0.pow(iter)
        }
        ++iter
    }
    return value.toInt()
}

/**
 * It converts [hex] into bytes as [String].
 * */
private fun hexToBytes(hex: String): String =
    when (hex.toLowerCase()) {
        "0" -> "0000"
        "1" -> "0001"
        "2" -> "0010"
        "3" -> "0011"
        "4" -> "0100"
        "5" -> "0101"
        "6" -> "0110"
        "7" -> "0111"
        "8" -> "1000"
        "9" -> "1001"
        "a" -> "1010"
        "b" -> "1011"
        "c" -> "1100"
        "d" -> "1101"
        "e" -> "1110"
        else -> "1111"
    }