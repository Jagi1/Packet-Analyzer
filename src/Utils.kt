package analizator

import kotlin.math.pow

/**
 * It converts [bytes] into [Int] value.
 * Example: 00011100 = 8 + 16 + 32 = 56
 * */
fun bytesToDouble(bytes: String): Int {
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