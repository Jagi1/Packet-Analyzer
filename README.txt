======================================================================
PDP - packet decoder protocol
======================================================================
1. Wstępne informacje.
Jest to protokół służący do przesyłu pakietów w celu ich dekodowania.
Stosowany jest dla architektury typu klient - serwer. Obsługiwany jest
na porcie 1057.
======================================================================
2. Komunikacja.
Komunikacja jest inicjalizowana przez klienta poprzez wysłanie
następującej wiadomości:
PDP:INIT:[wersja_protokołu]
Następnie serwer odpowiada odpowiednim kodem:
PDP:[kod_zwrotny]
Następnie klient wysyła typ pakietu:
PDP:[typ_pakietu]
Serwer odpowiada kodem mówiącym o tym, czy może obsłużyć dany protokół:
PDP[kod_zwortny]
Następnie klient wysyła pakiet do zdekodowania:
[pakiet]
Po odebraniu pakietu, serwer odsyła zdekodowane nagłówki pakietu.
[nagłówek_1]
[nagłówek_2]
[nagłówek_3]
Serwer kończy wysyłanie nagłówków odsyłając komunikat kończący
komunikację:
PDP:END
======================================================================
3. Wersje protokołu.
1.0
======================================================================
4. Kody zwrotne.
20 - dana wersja protokołu jest wspierana przez serwer
30 - dana wersja protokołu nie jest wspierana przez serwer
======================================================================
5. Przykładowa komunikacja.
Klient -> Serwer
PDP:INIT:1.0
Serwer -> Klient
PDP:20
Klient -> Serwer
PDP:ARP
Serwer -> Klient
PDP:21
Klient -> Serwer
b4 6b fc 8d cd 5e 00 00 ca 11 22 33 08 00 45 00 00 28 6d c7 40 00 80
06 79 76 c0 a8 00 64 5b 79 f7 0c
Serwer -> Klient
[informacje_o_zdekodowanym_nagłówku_EthernetII]
Serwer -> Klient
[informacje_o_zdekodowanym_nagłówku_IPv4]
Serwer -> Klient
PDP:END
======================================================================
6. Dodatkowe informacje.
Protokół wspiera dekodowanie następujących nagłówków protokołów:
- EthernetII,
- IPv4,
- IPv6,
- ARP,
- RARP,
- TCP,
- UDP,
- DHCP,
- DNS,
- ICMP,
- L2TP.
Protokół nie informuje serwera o tym w jakiej formie pakiet został
wysłany (binarnej czy heksadecymalnej). Serwer powinien się tym zająć.
Protokół nie określa również protokołów IPv4 / IPv6 / TCP / UDP
zawartych w pakiecie. Serwer analizując kolejne bajty powinien
wywnioskować jaki protokół znajduje się na wyższej warstwie modelu
sieciowego.
======================================================================