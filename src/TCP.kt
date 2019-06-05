package analizator

import java.io.PrintWriter

fun analyzeTCP(pw: PrintWriter, datagram: String?) = datagram?.let {
    var response = "TCP:\n"
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