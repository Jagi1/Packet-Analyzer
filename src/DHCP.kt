package analizator

import java.io.PrintWriter


/**
 * This method decode [header] of DHCP protocol and sends back it decoded to client with [PrintWriter].
 *
 * DHCP header structure:
 *   Message type --------------------- 1 bytes
 *   Hardware type -------------------- 1 bytes
 *   Hardware address length ---------- 1 bytes
 *   Hops ----------------------------- 1 bytes
 *   Transaction ID ------------------- 4 bytes
 *   Seconds elapsed ------------------ 2 bytes
 *   Bootp flags ---------------------- 2 bytes
 *   Client IP address ---------------- 4 bytes
 *   Your (client) IP address --------- 4 bytes
 *   Next server IP address ----------- 4 bytes
 *   Relay agent IP address ----------- 4 bytes
 *   Client MAC address --------------- 6 bytes
 *   Client hardware address padding -- 10 bytes
 *   Server host name ----------------- 64 bytes
 *   Boot file name ------------------- 128 bytes
 *   Magic cookie --------------------- 4 bytes
 *   Producent options ---------------- rest of bytes
 * */

fun analyzeDHCP(pw: PrintWriter, header: String): Int {
    var response = "Analyzed DHCP header:\n"
    var mType = header.substring(0, 2).toInt(16)
    val hType = header.substring(2, 4).toInt(16)
    val hAddrLen = header.substring(4, 6).toInt(16)
    val hops = header.substring(6, 8).toInt(16)
    val tranID = "0x" + header.substring(8, 16)
    val secElaps = header.substring(16, 20).toInt(16)
    val bootFlags = "0x" + header.substring(20, 24)
    val clientIP = header.substring(24, 32).chunked(2).map { it.toInt(16) }.joinToString(separator = ".")
    val yourIP = header.substring(32, 40).chunked(2).map { it.toInt(16) }.joinToString(separator = ".")
    val nextServerIP = header.substring(40, 48).chunked(2).map { it.toInt(16) }.joinToString(separator = ".")
    val relayAgentIP = header.substring(48, 56).chunked(2).map { it.toInt(16) }.joinToString(separator = ".")
    val clientMAC = header.substring(56, 68).chunked(2).joinToString(separator = ":")
    //val clientMACpadding = header.substring(68, 88)
    val serverHostName = hexToASCII(header.substring(88, 216))
    val bootFileName = hexToASCII(header.substring(216, 472))
    val magicCookie = if (header.substring(472, 480) == "63825363") "DHCP" else "Unknown"
    //val restOptions = header.substring(480, header.length)
    response += "   Message type: $mType\n"
    response += "   Hardware type: $hType\n"
    response += "   Hardware address length: $hAddrLen\n"
    response += "   Hops: $hops\n"
    response += "   Transaction ID: $tranID\n"
    response += "   Seconds elapsed: $secElaps\n"
    response += "   Bootp flags: $bootFlags\n"
    response += "   Client IP address: $clientIP\n"
    response += "   Your (client) IP address: $yourIP\n"
    response += "   Next server IP address: $nextServerIP\n"
    response += "   Relay agent IP address: $relayAgentIP\n"
    response += "   Client MAC address: $clientMAC\n"
    //response += "   Client hardware address padding: $clientMACpadding\n"
    response += "   Server host name: $serverHostName\n"
    response += "   Boot file name: $bootFileName\n"
    response += "   Magic cookie: $magicCookie\n"
    //response += "   Producent options: $restOptions\n"
    pw.println(response)
    return 1
}
