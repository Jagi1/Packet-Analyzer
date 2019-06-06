package analizator

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.Socket

fun main() = Socket("localhost", 11000).run {
    val pw = PrintWriter(getOutputStream(), true)
    val br = BufferedReader(InputStreamReader(getInputStream()))
    pw.println(ethernetII_IPV4_TCP)
    getResponse(br)
    pw.close()
    br.close()
    close()
}

fun getResponse(br: BufferedReader) {
    var line: String? = br.readLine()
    while (line != null) {
        System.out.println("$line")
        line = br.readLine()
    }
    Thread.sleep(200)
    line = br.readLine()
    while (line != null) {
        System.out.println("$line")
        line = br.readLine()
    }
    Thread.sleep(200)
    line = br.readLine()
    while (line != null) {
        System.out.println("$line")
        line = br.readLine()
    }
}