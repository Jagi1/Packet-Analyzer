package analizator

import java.io.PrintWriter

/**
 * This method decode [header] of TCP protocol and sends back it decoded to client with [PrintWriter].
 *
 * TCP header structure:
 *   Source port --------------------- 2 bytes - header range 0....3
 *   Destination port ---------------- 2 bytes - header range 4....7
 *   Sequence number ----------------- 4 bytes - header range 8...15
 *   Acknowledge number -------------- 4 bytes - header range 16..23
 *   Offset -------------------------- 4 bits -- header range 24..24
 *   Reserved ------------------------ 3 bits -- header range 24..24
 *   ECN-nonce (NS) ------------------ 1 bit --- header range 24..24
 *   Congestion Window Reduced (CWR) - 1 bit --- header range 25..25
 *   ECN-echo (ECE) ------------------ 1 bit --- header range 25..25
 *   Urgent pointer (URG) ------------ 1 bit --- header range 25..25
 *   Acknowledgement (ACK) ----------- 1 bit --- header range 25..25
 *   Push function (PSH) ------------- 1 bit --- header range 26..26
 *   Reset (RST) --------------------- 1 bit --- header range 26..26
 *   Synchronize (SYN) --------------- 1 bit --- header range 26..26
 *   Last packet (FIN) --------------- 1 bit --- header range 26..26
 *   Window size --------------------- 2 bytes - header range 27..30
 *   Checksum ------------------------ 2 bytes - header range 31..34
 *   Urgent pointer ------------------ 2 bytes - header range 35..38
 * */
fun analyzeTCP(pw: PrintWriter, header: String?) = header?.let {
    var response = "Analyzed TCP header:\n"
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
    val windowSize = "${it[27]}${it[28]}${it[29]}${it[30]}".toInt(16)
    val checkSum = "0x${it[31]}${it[32]}${it[33]}${34}"
    val urgentPointer = "${it[35]}${it[36]}${it[37]}${it[38]}".toInt(16)
    response += "    Source port: $sPort\n"
    response += "    Destination port: $dPort\n"
    response += "    Sequence number: $seqNumber\n"
    response += "    Acknowledgment number: $ackNumber\n"
    response += "    Offest: $offset\n"
    response += "    Flags:\n"
    response += when {
        "${reserved[0]}${reserved[1]}${reserved[2]}" == "000" -> "    ${reserved[0]}${reserved[1]}${reserved[2]}. .... .... = Reserved: Not set\n"
        else -> "    ${reserved[0]}${reserved[1]}${reserved[2]}. .... .... = Reserved: Set\n"
    }
    response += when (nonce) {
        "0" -> "    ...$nonce .... .... = Nonce: Not set\n"
        else -> "    ...$nonce .... .... = Nonce: Set\n"
    }
    response += when (congestion) {
        "0" -> "    .... $congestion... .... = Congestion Window Reduced (CWR): Not set\n"
        else -> "    .... $congestion... .... = Congestion Window Reduced (CWR): Set\n"
    }
    response += when (ecnEcho) {
        "0" -> "    .... .$ecnEcho.. .... = ECN-Echo: Not set\n"
        else -> "    .... .$ecnEcho.. .... = ECN-Echo: Set\n"
    }
    response += when (urgent) {
        "0" -> "    .... ..$urgent. .... = Urgent: Not set\n"
        else -> "    .... ..$urgent. .... = Urgent: Set\n"
    }
    response += when (acknowledgement) {
        "0" -> "    .... ...$acknowledgement .... = Acknowledgement: Not set\n"
        else -> "    .... .... ...$acknowledgement = Acknowledgement: Set\n"
    }
    response += when (push) {
        "0" -> "    .... .... $push... = Push: Not set\n"
        else -> "    .... .... $push... = Push: Set\n"
    }
    response += when (reset) {
        "0" -> "    .... .... .$reset.. = Reset: Not set\n"
        else -> "    .... .... .$reset.. = Reset: Set\n"
    }
    response += when (syn) {
        "0" -> "    .... .... ..$syn. = Syn: Not set\n"
        else -> "    .... .... ..$syn. = Syn: Set\n"
    }
    response += when (fin) {
        "0" -> "    .... .... ...$fin = Fin: Not set\n"
        else -> "    .... .... ...$fin = Fin: Set\n"
    }
    response += "    Window size value: $windowSize\n"
    response += "    Checksum: $checkSum\n"
    response += "    Urgent pointer: $urgentPointer\n"
    pw.println(response)
}