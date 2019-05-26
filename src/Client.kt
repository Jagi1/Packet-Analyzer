package analizator

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.lang.IllegalStateException
import java.net.Socket

fun main() = Socket("localhost", 11000).run {
    val pw = PrintWriter(getOutputStream(), true)
    val br = BufferedReader(InputStreamReader(getInputStream()))
    val datagramIPV4 = "45 00 00 4e f7 fa 40 00 38 06 9d 33 d4 b6 18 1b " +
            "c0 a8 00 02 0b 54 b9 a6 fb f9 3c 57 c1 0a 06 c1 " +
            "80 18 00 e3 ce 9c 00 00 01 01 08 0a 03 a6 eb 01 " +
            "00 0b f8 e5 6e 65 74 77 6f 72 6b 20 70 72 6f 67 " +
            "72 61 6d 6d 69 6e 67 20 69 73 20 66 75 6e"
    val datagramTCP = "0b 54 89 8b 1f 9a 18 ec bb b1 64 f2 80 18 " +
            "00 e3 67 71 00 00 01 01 08 0a 02 c1 a4 ee " +
            "00 1a 4c ee 68 65 6c 6c 6f 20 3a 29"
    pw.println(datagramIPV4)
//    pw.println(datagramTCP)
    var datagramReceived: String? = ""
    var line: String? = br.readLine().replace(" ", "")
    try {
        while (line != null) {
            datagramReceived += line
            System.out.println(line)
            line = br.readLine().replace(" ", "")
        }
    } catch (e: IllegalStateException) {

    }
    pw.close()
    br.close()
    close()
}