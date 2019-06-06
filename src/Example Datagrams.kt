package analizator

val ethernetII = "b4 6b fc 8d cd 5e 00 00 ca 11 22 33 08 00"

val datagramTCP = "0b 54 89 8b 1f 9a 18 ec bb b1 64 f2 80 18 " +
        "00 e3 67 71 00 00 01 01 08 0a 02 c1 a4 ee " +
        "00 1a 4c ee 68 65 6c 6c 6f 20 3a 29"

val datagramIPV6 = "60 00 00 00 00 00 3b 00 fe 80 00 00 00 00 " +
        "00 00 70 8d fe 83 41 14 a5 12 20 01 00 00 41 37 " +
        "9e 50 80 00 f1 2a b9 c8 28 15"

val ethernetII_IPV6 = "b4 6b fc 8d cd 5e 00 00 ca 11 22 33 86 dd" +
        "60 00 00 00 00 00 3b 00 fe 80 00 00 00 00 " +
        "00 00 70 8d fe 83 41 14 a5 12 20 01 00 00 41 37 " +
        "9e 50 80 00 f1 2a b9 c8 28 15"

val ethernetII_IPV4 = "b4 6b fc 8d cd 5e 00 00 ca 11 22 33 08 00 " +
        "45 00 00 28 6d c7 40 00 80 06 79 76 c0 a8 00 64 5b 79 f7 0c "

val ethernetII_IPV4_TCP = "b4 6b fc 8d cd 5e 00 00 ca 11 22 33 08 00 " + // EthernetII
        "45 00 00 28 6d c7 40 00 80 06 79 76 c0 a8 00 64 5b 79 f7 0c " + // IPV4
        "f2 d9 01 bb 24 fc 98 bb 18 3f 30 29 50 11 00 ff a0 8d 00 00 " // TCP

val ethernetII_IPV4_UDP = "b4 6b fc 8d cd 5e 00 00 ca 11 22 33 08 00" + // EthernetII
        "45 00 01 4f 38 7b 40 00 80 11 3e 8f c0 a8 00 64 ac d9 14 ae" + // IPV4
        "d5 c8 01 bb 01 3b 61 66" // UDP