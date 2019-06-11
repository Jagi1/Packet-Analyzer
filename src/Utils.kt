package analizator

import kotlin.math.pow

val projectPath = System.getProperty("user.dir")!!

/**
 * It converts [bytes] into [Int] value.
 * Example: 00011100 = 8 + 16 + 32 = 56
 * */
fun bytesToInt(bytes: String): Int {
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
fun hexToBytes(hex: String): String =
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

/**
 * Converts [bytes] into hex as [String].
 * */
fun bytesToHex(bytes: String): String =
    when (bytes.toLowerCase()) {
        "0000" -> "0"
        "0001" -> "1"
        "0010" -> "2"
        "0011" -> "3"
        "0100" -> "4"
        "0101" -> "5"
        "0110" -> "6"
        "0111" -> "7"
        "1000" -> "8"
        "1001" -> "9"
        "1010" -> "a"
        "1011" -> "b"
        "1100" -> "c"
        "1101" -> "d"
        "1110" -> "e"
        else -> "f"
    }

fun hexToByteString(hexStr: String): String {
    val output = StringBuilder("")
    var i = 0
    while (i < hexStr.length) {
        output.append(hexToBytes(hexStr.substring(i, i + 1)))
        i += 1
    }

    return output.toString()
}

fun hexToASCII(hexStr: String): String {
    val output = StringBuilder("")

    var i = 0
    while (i < hexStr.length) {
        val str = hexStr.substring(i, i + 2)
        output.append(Integer.parseInt(str, 16).toChar())
        i += 2
    }

    return output.toString()
}

/**
 * Converts [packet] from binary type to hexadecimal type.
 * */
fun convertPacketBinToHex(packet: String): String =
    packet.chunked(4).joinToString { bytesToHex(it) }

fun convertPacketHexToBin(packet: String): String =
        packet.chunked(1).joinToString { hexToBytes(it) }

/**
 * This function checks if packet was sent is binary or hexadecimal.
 * It returns [Int]:
 * - 0 - packet is hexadecimal type
 * - 1 - packet is binary type
 * */
fun checkBinOrHex(packet: String): Int {
    packet.forEach {
        if (it == '0' || it == '1') { }
        else return 0
    }
    return 1
}