package analizator

import java.io.File
import java.io.PrintWriter

/**
 * This method decode [header] of DNS protocol and sends back it decoded to client with [PrintWriter].
 *
 * DNS header structure:
 *   Transaction ID ------------------- 2 bytes
 *   Flags ---------------------------- 2 bytes
 *      Response: Message is a response
 *      Opcode: Standard query (0)
 *      Authoritative: Server is not an authority for domain
 *      Truncated: Message is not truncated
 *      Recursion desired: Do query recursively
 *      Recursion available: Server can do recursive queries
 *      Z: reserved (0)
 *      Answer authenticated: Answer/authority portion was not authenticated by the server
 *      Non-authenticated data: Unacceptable
 *      Reply code: No error (0)
 *   Question Count -------------------- 2 bytes
 *   Answer Count ---------------------- 2 bytes
 *   Authority Count ------------------- 2 bytes
 *   Additional Count ------------------ 2 bytes
 *   Queries --------------------------- (value from Question Count) bytes
 *   Answers --------------------------- (value from Answer Count) bytes
 *   Authoritative --------------------- (value from Authority Count) bytes
 *   Additionals ----------------------- (value from Additional Count) bytes
 * */

fun analyzeDNS(pw: PrintWriter, header: String, length: Int): Int {
    var response = "Analyzed DNS header:\n"
    var tranID = "0x" + header.substring(0, 4)
    val flags = header.substring(4, 8)
    val questionCount = header.substring(8, 12).toInt(16)
    val answerCount = header.substring(12, 16).toInt(16)
    val authorityCount = header.substring(16, 20).toInt(16)
    val additionalCount = header.substring(20, 24).toInt(16)
    var question = ""

    if(length != -1){
        val DNSQueryLength = length - 8 - 16 // UDP header length is always 8 bytes, for DNS query is 16 bytes to subtract
        question = hexToASCII(header.substring(24, 24 + DNSQueryLength*2))
//    var temp = 20 + questionCount
//    val answer = header.substring(temp, temp + answerCount)
//    temp += answerCount
//    val authority = header.substring(temp, temp + authorityCount)
//    temp += authorityCount
//    val additional = header.substring(temp, temp + additionalCount)
    }

    response += "   Transaction ID: $tranID\n"
    response += "   Flags: $flags\n"
    response += "   Question Count: $questionCount\n"
    response += "   Answer Count: $answerCount\n"
    response += "   Authority Count: $authorityCount\n"
    response += "   Additional Count: $additionalCount\n"
    response += "   Queries: $question\n"
//    response += "   Answers: $answer\n"
//    response += "   Authoritative: $authority\n"
//    response += "   Additionals: $additional\n"
    pw.println(response)
    File("$projectPath\\src\\logs\\HeadersSent.txt").run {
        appendText("DNS: $header\n$response\n", Charsets.UTF_8)
    }
    return 1
}


//fun main() {
//    val header = "00010800060400015254001234560a00020f0000000000000a000205"
//    val test = header.substring(28, 36)
//    println(test)
//    val result2 = test.chunked(2).map { it.toInt(16) }.joinToString(separator = ".")
//    println(result2)
//}