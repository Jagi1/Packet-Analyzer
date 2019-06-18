package analizator

import java.io.File
import java.io.PrintWriter

/**
 * This method decode [header] of DNS protocol and sends back it decoded to client with [PrintWriter].
 *
 * DNS header structure:
 *   Transaction ID ------------------- 2 bytes
 *   Flags ---------------------------- 2 bytes
 *   Question Count -------------------- 2 bytes
 *   Answer Count ---------------------- 2 bytes
 *   Authority Count ------------------- 2 bytes
 *   Additional Count ------------------ 2 bytes
 *   Queries --------------------------- (value from Question Count) bytes
 *   Answers --------------------------- (value from Answer Count) bytes
 *   Authoritative --------------------- (value from Authority Count) bytes
 *   Additionals ----------------------- (value from Additional Count) bytes
 * */

// only DNS Query has more details
fun analyzeDNS(pw: PrintWriter, header: String, length: Int): Int {
    var response = "Analyzed DNS header:\n"
    var tranID = "0x" + header.substring(0, 4)
    var flags = header.substring(4, 8)
    val bFlags = hexToByteString(flags)
    flags = "Flags: 0x$flags\n" +
            "      Response: ${bFlags.substring(0, 1)}\n" +
            "      Opcode: ${bFlags.substring(1, 5)}\n" +
            "      Authoritative: ${bFlags.substring(5, 6)}\n" +
            "      Truncated: ${bFlags.substring(6, 7)}\n" +
            "      Recursion desired: ${bFlags.substring(7, 8)}\n" +
            "      Recursion available: ${bFlags.substring(8, 9)}\n" +
            "      Z: ${bFlags.substring(9, 10)}\n" +
            "      Answer authenticated: ${bFlags.substring(10, 11)}\n" +
            "      Non-authenticated data: ${bFlags.substring(11, 12)}\n" +
            "      Reply code: ${bFlags.substring(12, 16)}"

    val questionCount = header.substring(8, 12).toInt(16)
    val answerCount = header.substring(12, 16).toInt(16)
    val authorityCount = header.substring(16, 20).toInt(16)
    val additionalCount = header.substring(20, 24).toInt(16)
    var data = header.substring(24)

    // length from analyze UDP
    if(length != -1){
        val DNSQueryNameSignsCount = (length - 8 - 16) * 2 // UDP header length is always 8 bytes, for DNS query is 16 bytes to subtract
        val questionName = hexToASCII(data.substring(0, DNSQueryNameSignsCount))
        val questionType = data.substring(DNSQueryNameSignsCount, DNSQueryNameSignsCount+4)
        val DNSQueryEnd = DNSQueryNameSignsCount+8
        val questionClass = data.substring(DNSQueryNameSignsCount+4, DNSQueryEnd)
        data = "Queries:\n" +
                "       Name: $questionName\n" +
                "       Type: 0x$questionType\n" +
                "       Class: 0x$questionClass\n" +
                "   Rest of data: ${data.substring(DNSQueryEnd)}"
//    var temp = question.length + questionCount
//    val answer = header.substring(temp, temp + answerCount)
//    temp += answerCount
//    val authority = header.substring(temp, temp + authorityCount)
//    temp += authorityCount
//    val additional = header.substring(temp, temp + additionalCount)
//    data += "   Answers: $answer\n"
//    data += "   Authoritative: $authority\n"
//    data += "   Additionals: $additional\n"
    }

    response += "   Transaction ID: $tranID\n"
    response += "   $flags\n"
    response += "   Question Count: $questionCount\n"
    response += "   Answer Count: $answerCount\n"
    response += "   Authority Count: $authorityCount\n"
    response += "   Additional Count: $additionalCount\n"
    response += "   $data\n"
    pw.println(response)
    logDecoding(header, response)
    return 1
}