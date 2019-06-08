package analizator

val ethernetII = "b4 6b fc 8d cd 5e 00 00 ca 11 22 33 08 00"

val datagramTCP = "0b 54 89 8b 1f 9a 18 ec bb b1 64 f2 80 18 " +
        "00 e3 67 71 00 00 01 01 08 0a 02 c1 a4 ee " +
        "00 1a 4c ee 68 65 6c 6c 6f 20 3a 29"

val datagramIPV6 = "60 00 00 00 00 00 3b 00 fe 80 00 00 00 00 " +
        "00 00 70 8d fe 83 41 14 a5 12 20 01 00 00 41 37 " +
        "9e 50 80 00 f1 2a b9 c8 28 15"

val ethernetII_IPV4 = "b4 6b fc 8d cd 5e 00 00 ca 11 22 33 08 00 " +
        "45 00 00 28 6d c7 40 00 80 06 79 76 c0 a8 00 64 5b 79 f7 0c "

val ethernetII_IPV6 = "b4 6b fc 8d cd 5e 00 00 ca 11 22 33 86 dd" + // EthernetII
        "60 00 00 00 00 00 3b 00 fe 80 00 00 00 00 " + // IPV6
        "00 00 70 8d fe 83 41 14 a5 12 20 01 00 00 41 37 " + // IPV6
        "9e 50 80 00 f1 2a b9 c8 28 15" // IPV6

val ethernetII_IPV4_TCP = "b4 6b fc 8d cd 5e 00 00 ca 11 22 33 08 00 " + // EthernetII
        "45 00 00 28 6d c7 40 00 80 06 79 76 c0 a8 00 64 5b 79 f7 0c " + // IPV4
        "f2 d9 01 bb 24 fc 98 bb 18 3f 30 29 50 11 00 ff a0 8d 00 00 " // TCP

val ethernetII_IPV4_UDP = "b4 6b fc 8d cd 5e 00 00 ca 11 22 33 08 00" + // EthernetII
        "45 00 01 4f 38 7b 40 00 80 11 3e 8f c0 a8 00 64 ac d9 14 ae" + // IPV4
        "d5 c8 01 bb 01 3b 61 66" // UDP

val ARP = "00 01 08 00 06 04 00 01 52 54 00 12 34 56 0a 00 " +
        "02 0f 00 00 00 00 00 00 0a 00 02 05"

val RARP = "00 01 08 00 06 04 00 03 00 00 a1 12 dd 88 00 00 " +
        "00 00 00 00 a1 12 dd 88 00 00 00 00"

val ICMP = "08 00 16 b7 35 37 00 01 3f 9c b7 57 00 00 00 00 " +
        "f0 49 06 00 00 00 00 00 10 11 12 13 14 15 16 17 " +
        "18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 " +
        "28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37"

val DHCP = "02 01 06 01 0a 06 8a af 00 00 00 00 00 00 00 00 " +
        "0a fb 17 8b 56 40 91 a6 0a c2 8f 01 e0 a1 d7 18 " +
        "c2 72 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
        "00 00 00 00 00 00 00 00 00 00 00 00 63 82 53 63 " +
        "35 01 02 36 04 56 40 91 a6 03 04 0a fb 17 01 01 " +
        "04 ff ff ff 00 11 0d 38 36 2e 36 34 2e 32 33 33 " +
        "2e 31 33 33 0e 27 31 7c 63 61 40 31 2e 31 2e 31 " +
        "2e 31 7c 31 2e 31 2e 31 2e 31 7c 74 6f 74 6f 40 " +
        "6e 65 75 66 2e 63 6f 6d 7c 64 6d 30 31 28 0b 68 " +
        "75 61 77 65 69 35 36 30 30 74 33 04 00 00 38 40 " +
        "06 08 6d 00 42 0a 6d 00 42 14 ff"

val DNS_query = "00 02 01 00 00 01 00 00 00 00 00 00 05 73 74 61 " +
        "74 73 07 6e 65 75 66 62 6f 78 04 6e 65 75 66 02 " +
        "66 72 00 00 1c 00 01"
val DNS_response = "00 02 81 80 00 01 00 01 00 01 00 00 05 73 74 61 " +
        "74 73 07 6e 65 75 66 62 6f 78 04 6e 65 75 66 02 " +
        "66 72 00 00 1c 00 01 c0 0c 00 05 00 01 00 00 00 " +
        "76 00 1f 10 64 62 70 6f 6c 6c 69 6e 67 2d 6d 61 " +
        "73 74 65 72 04 64 69 61 67 03 73 66 72 03 6e 65 " +
        "74 00 c0 44 00 06 00 01 00 00 02 5a 00 2a 04 64 " +
        "6e 73 31 07 67 61 6f 6c 61 6e 64 c0 4d 04 72 6f " +
        "6f 74 c0 5e 77 fd cd 09 00 01 51 80 00 00 70 80 " +
        "00 12 75 00 00 01 51 80"

val UDP_DNS_query = "9b 74 00 35 00 2f dd bb $DNS_query"

val L2TP = "c8 02 00 2a 05 f7 00 00 00 01 00 01 80 08 00 00 " +
        "00 00 00 03 80 16 00 00 00 0d 01 dc 48 5b 13 ea " +
        "cb 71 a3 8f a9 dd 2a 74 fc be"

val ethernetII_ARP = "ff ff ff ff ff ff 00 07 0d af f4 54 " +
        "08 06 00 01 08 00 06 04 00 01 00 07 0d af f4 54 " +
        "18 a6 ac 01 00 00 00 00 00 00 18 a6 ae ed 03 01 " +
        "04 00 00 00 00 02 01 00 03 02 00 00 05 01 03 01"