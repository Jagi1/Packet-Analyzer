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

val ethernetII_IPV6_bin = "101101000110101111111100100011011100110101" +
        "011110000000000000000011001010000100010010001000110011100001" +
        "101101110101100000000000000000000000000000000000000000000000" +
        "111011000000001111111010000000000000000000000000000000000000" +
        "000000000000000000011100001000110111111110100000110100000100" +
        "010100101001010001001000100000000000010000000000000000010000" +
        "010011011110011110010100001000000000000000111100010010101010" +
        "111001110010000010100000010101"

val ARP = "00 01 08 00 06 04 00 01 52 54 00 12 34 56 0a 00 " +
        "02 0f 00 00 00 00 00 00 0a 00 02 05"

val RARP = "00 01 08 00 06 04 00 03 00 00 a1 12 dd 88 00 00 " +
        "00 00 00 00 a1 12 dd 88 00 00 00 00"

val ICMP = "08 00 16 b7 35 37 00 01 3f 9c b7 57 00 00 00 00 " +
        "f0 49 06 00 00 00 00 00 10 11 12 13 14 15 16 17 " +
        "18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 " +
        "28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37"

// echo request
val IPv6_ICMPv6_128 = "60 01 5c 64 00 40 3a 40 fe c0 00 00 00 00 00 00" +
        "50 54 00 ff fe 12 34 56 fe c0 00 00 00 00 00 00 " +
        "00 00 00 00 00 00 00 02 " + // IPv6
        "80 00 5d 6e 35 50 00 01 af 9d b7 57 00 00 00 00 " +
        "3a bd 0b 00 00 00 00 00 10 11 12 13 14 15 16 17 " +
        "18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 " +
        "28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37"

// echo reply
val IPv6_ICMPv6_129 = "60 00 00 00 00 40 3a ff fe c0 00 00 00 00 00 00 " +
        "00 00 00 00 00 00 00 02 fe c0 00 00 00 00 00 00 " +
        "50 54 00 ff fe 12 34 56 " + // IPv6
        "81 00 5c 6e 35 50 00 01 af 9d b7 57 00 00 00 00 " +
        "3a bd 0b 00 00 00 00 00 10 11 12 13 14 15 16 17 " +
        "18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 " +
        "28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37"

val IPv6_ICMPv6_135 = "60 00 00 00 00 20 3a ff fe c0 00 00 00 00 00 00 " +
        "50 54 00 ff fe 12 34 56 ff 02 00 00 00 00 00 00 " +
        "00 00 00 01 ff 00 00 02 " + // IPv6
        "87 00 71 a0 00 00 00 00 fe c0 00 00 00 00 00 00 " +
        "00 00 00 00 00 00 00 02 01 01 52 54 00 12 34 56"

val IPv6_ICMPv6_136 = "60 00 00 00 00 20 3a ff fe c0 00 00 00 00 00 00 " +
        "00 00 00 00 00 00 00 02 fe c0 00 00 00 00 00 00 " +
        "50 54 00 ff fe 12 34 56 " + // IPv6
        "88 00 c3 47 e0 00 00 00 fe c0 00 00 00 00 00 00 " +
        "00 00 00 00 00 00 00 02 02 01 52 56 00 00 00 02"

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

val ethernetII_IPV4_TCP = "b4 6b fc 8d cd 5e 00 00 ca 11 22 33 08 00 " + // EthernetII
        "45 00 00 28 6d c7 40 00 80 06 79 76 c0 a8 00 64 5b 79 f7 0c " + // IPV4
        "f2 d9 01 bb 24 fc 98 bb 18 3f 30 29 50 11 00 ff a0 8d 00 00 " // TCP

val ethernetII_IPV4_UDP = "b4 6b fc 8d cd 5e 00 00 ca 11 22 33 08 00" + // EthernetII
        "45 00 01 4f 38 7b 40 00 80 11 3e 8f c0 a8 00 64 ac d9 14 ae" + // IPV4
        "d5 c8 01 bb 01 3b 61 66" // UDP

// example packets:
val ethernetII_IPv6_ICMPv6_128 = "00 60 97 07 69 ea 00 00 86 05 80 da 86 dd $IPv6_ICMPv6_128"
val ethernetII_IPv6_ICMPv6_129 = "00 60 97 07 69 ea 00 00 86 05 80 da 86 dd $IPv6_ICMPv6_129"
val ethernetII_IPv6_ICMPv6_135 = "00 60 97 07 69 ea 00 00 86 05 80 da 86 dd $IPv6_ICMPv6_135"
val ethernetII_IPv6_ICMPv6_136 = "00 60 97 07 69 ea 00 00 86 05 80 da 86 dd $IPv6_ICMPv6_136"

val ethernetII_ARP = "ff ff ff ff ff ff 00 07 0d af f4 54 " +
        "08 06 00 01 08 00 06 04 00 01 00 07 0d af f4 54 " +
        "18 a6 ac 01 00 00 00 00 00 00 18 a6 ae ed 03 01 " +
        "04 00 00 00 00 02 01 00 03 02 00 00 05 01 03 01"

val ethernetII_IPV4_ICMP = "b4 6b fc 8d cd 5e 00 00 ca 11 22 33 08 00 45 " +
        "20 00 3c 00 00 00 00 37 01 b2 e5 08 08 08 08 c0 " +
        "a8 00 04 00 00 55 57 00 01 00 04 61 62 63 64 65 " +
        "66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 " +
        "76 77 61 62 63 64 65 66 67 68 69"

val ethernetII_IPV4_UDP_DNS = "0000ca112233b46bfc8dcd5e08004" +
        "50000424fa100008011cea8c0a8000459e701cefb750035002e" +
        "11dbb081010000010000000000000666702d61666409617a757" +
        "26565646765036e65740000010001"

val ethernetII_IVP4_UDP_DHCP = "000b8201fc42000874adf19b0800450001480445000080110000c0a80001c0a8" +
        "000a00430044013422330201060000003d1d0000000000000000c0a8000ac0a8000100000000000b8201fc4" +
        "200000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000000000000000638253633501020104ffffff003a04" +
        "000007083b0400000c4e330400000e103604c0a80001ff00000000000000000000000000000000000000000" +
        "00000000000"

val ethernetII_RARP = "ffffffffffff0000a112dd88080600010800060400030000a112dd88000000000000a112d" +
        "d8800000000000000000000000000000000000000000000"

val ethernetII_PPP_IPv4_UDP_DNS = "00 17 33 61 00 00 e0 a1 d7 18 c2 73 88 64 " + // ethernetII
        "11 00 1b 3d 00 45 00 21 " + // PPP
        "45 00 00 43 14 8a 40 00 40 11 25 57 5f 88 f2 36 " +
        "6d 00 42 0a " + //IPv4
        "9b 74 00 35 00 2f dd bb " + // UDP
        "00 02 01 00 00 01 00 00 00 00 00 00 05 73 74 61 " +
        "74 73 07 6e 65 75 66 62 6f 78 04 6e 65 75 66 02 " +
        "66 72 00 00 1c 00 01" // DNS query

val ethernetII_IPv6_UDP_DNS = "00 60 97 07 69 ea 00 00 86 05 80 da 86 dd " +// Ethernet II
        "60 00 00 00 00 27 11 40 3f fe 05 07 00 00 00 01 " +
        "02 00 86 ff fe 05 80 da 3f fe 05 01 48 19 00 00 " +
        "00 00 00 00 00 00 00 42 " + // IPv6
        "09 5d 00 35 00 27 46 b7 " + // UDP
        "00 06 01 00 00 01 00 00 00 00 00 00 03 77 77 77 " +
        "05 79 61 68 6f 6f 03 63 6f 6d 00 00 0f 00 01" // DNS