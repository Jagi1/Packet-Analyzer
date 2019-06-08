package analizator

import java.io.PrintWriter

/**
 * This method decode [header] of L2TP protocol and sends back it decoded to client with [PrintWriter].
 *
 * L2TP header structure:
 *   Packet Type ---------------- 2 bytes
 *      1... .... .... .... = Type: 1
 *      .1.. .... .... .... = Length Bit: Length field is present
 *      .... 1... .... .... = Sequence Bit: Ns and Nr fields are present
 *      .... ..0. .... .... = Offset bit: Offset size field is not present
 *      .... ...0 .... .... = Priority: No priority
 *      .... .... .... 0010 = Version: 2
 *   Length --------------------- 2 bytes (optional)
 *   Tunnel ID ------------------ 2 bytes
 *   Session ID ----------------- 2 bytes
 *   Ns ------------------------- 2 bytes (optional)
 *   Nr ------------------------- 2 bytes (optional)
 *   Offset Size ---------------- 2 bytes (optional)
 *   Offset Padding ------------- 2 bytes (optional)
 *   Data ----------------------- ?? bytes
 * */

fun analyzeL2TP(pw: PrintWriter, header: String): Int {
    var response = "Analyzed L2TP header:\n"
    var packetFlags = hexToByteString(header.substring(0, 4))
    val fType = packetFlags.substring(0, 1)
    val fLength = packetFlags.substring(1, 2)
    val fSequence = packetFlags.substring(4, 5)
    val fOffset = packetFlags.substring(6, 7)
    val fPriority = packetFlags.substring(7, 8)
    val fVersion = bytesToInt(packetFlags.substring(12, 16))

    response += "    Packet Flags: $packetFlags\n"
    response += "       Type: $fType\n" +
                "       Length Bit: $fLength\n" +
                "       Sequence Bit: $fSequence\n" +
                "       Offset bit: $fOffset\n" +
                "       Priority: $fPriority\n" +
                "       Version: $fVersion\n"
    var temp = 4
    var packetLength = -1
    if (fLength == "1") {
        packetLength = header.substring(temp, temp + 4).toInt(16)
        temp += 4
        response += "    Packet Length: $packetLength\n"
    }

    val tunnelID = header.substring(temp, temp + 4).toInt(16)
    temp += 4
    val sessionID = header.substring(temp, temp + 4).toInt(16)
    temp += 4
    response += "    Tunnel ID: $tunnelID\n"
    response += "    Session ID: $sessionID\n"

    var ns = -1
    var nr = -1
    if (fSequence == "1") {
        ns = header.substring(temp, temp + 4).toInt(16)
        temp += 4
        nr = header.substring(temp, temp + 4).toInt(16)
        temp += 4
        response += "    NS: $ns\n"
        response += "    NR: $nr\n"
    }
    var offsetSize = -1
    var offsetPad = -1
    if (fOffset == "1") {
        offsetSize = header.substring(temp, temp + 4).toInt(16)
        temp += 4
        offsetPad = header.substring(temp, temp + 4).toInt(16)
        temp += 4
        response += "    Offset Size: $offsetSize\n"
        response += "    Offset Padding: $offsetPad\n"
    }

    var data = header.substring(temp, header.length)
    var dataList = StringBuilder("")
    temp = 0
    while(true) {
        var dataFlags = hexToByteString(data.substring(0, 4))
        val dMandatory = dataFlags.substring(0,1)
        val dHidden = dataFlags.substring(1,2)
        val dLength = bytesToInt(dataFlags.substring(6,16))
        val dataLength = (dLength - 2) * 2
        if (dMandatory == "1" ){
            dataList.append("\t\t\tMandatory: True\n")
        } else {
            dataList.append("\t\t\tMandatory: False\n")
        }
        if (dHidden == "1" ){
            dataList.append("\t\t\tHidden: True\n")
        } else {
            dataList.append("\t\t\tHidden: False\n")
        }
        val tempData = data.substring(4, 4 + dataLength)
        dataList.append("\t\t\tVendor ID: " + tempData.substring(0, 4).toInt(16) + "\n")
        dataList.append("\t\t\tAVP Type: " + tempData.substring(4, 8).toInt(16) + "\n")
        dataList.append("\t\t\tMessage: " + tempData.substring(8, tempData.length) + "\n\n")
        temp = data.length - 4
        data = data.substring(4 + dataLength, data.length)
        if(temp == dataLength) {
            break
        }
    }
    response += "\t\tData:\n$dataList"
    pw.println(response)
    return 1
}
