import scapy.all as scapy
from binascii import hexlify, unhexlify
# import sys

#sys.stdout = open("txt_files/output.txt","w")      # vypis do .txt suboru

ramecCislo = 1
prve_tftp = 0

tftp_komunikacie = []
arp_komunikacie = []

IPAdresy = {
}

frame_types = {
}

ipv4_subprotocols = {
}

eth_subprotocols = {
}

SAPs = {
}

tcp_ports = {
}

udp_ports = {
}

icmp_codes = {
}

arp_opCode = {
    "01" : "request",
    "02" : "reply",
}


class TFTP:
    def __init__(self, srcPort, dstPort):
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.pocetKomunikacii = 0

class ARP:
    def __init__(self, srcMAC, dstMAC, srcIP, dstIP):
        self.srcMAC = srcMAC
        self.dstMAC = dstMAC
        self.srcIP = srcIP
        self.dstIP = dstIP
        self.pocetKomunikacii = 0


def load_from_files():
    with open("txt_files/ipv4_subprotocols.txt", "r") as file:
        for line in file:
            protNum, protocol = line.split(":", 1)
            protocol = protocol[0: -1]        #odstranenie \n
            ipv4_subprotocols[protNum] = protocol

    with open("txt_files/frame_types.txt", "r") as file:
        for line in file:
            protNum, protocol = line.split(":", 1)
            protocol = protocol[0: -1]        #odstranenie \n
            frame_types[protNum] = protocol

    with open("txt_files/eth_subprotocols.txt", "r") as file:
        for line in file:
            protNum, protocol = line.split(":", 1)
            protNum = int(protNum)
            protocol = protocol[0: -1]        #odstranenie \n
            eth_subprotocols[protNum] = protocol

    with open("txt_files/SAPs.txt", "r") as file:
        for line in file:
            protNum, protocol = line.split(":", 1)
            protocol = protocol[0: -1]        #odstranenie \n
            SAPs[protNum] = protocol

    with open("txt_files/tcp_ports.txt", "r") as file:
        for line in file:
            protNum, protocol = line.split(":", 1)
            protocol = protocol[0: -1]        #odstranenie \n
            tcp_ports[protNum] = protocol

    with open("txt_files/udp_ports.txt", "r") as file:
        for line in file:
            protNum, protocol = line.split(":", 1)
            protocol = protocol[0: -1]        #odstranenie \n
            udp_ports[protNum] = protocol

    with open("txt_files/icmp_codes.txt", "r") as file:
        for line in file:
            protNum, protocol = line.split(":", 1)
            protocol = protocol[0: -1]        #odstranenie \n
            icmp_codes[protNum] = protocol


def add_src_ipv4_address(adresa):     # prida IP adresu odosielatela do dictionary
    global IPAdresy
    if adresa in IPAdresy:
        IPAdresy[adresa] += 1
    else:
        IPAdresy[adresa] = 1


def vypis_src_ipv4():
    global IPAdresy
    if not IPAdresy:        #ak je list prazdny
        return
    maxNum = 0
    maxIP = ""
    print("IP adresy odosielajucich uzlov:")
    for addr in IPAdresy:
        print(str(addr),"  ->  ", IPAdresy[addr],"packets")                # 3a
        if maxNum < IPAdresy[addr]:     # 3b
            maxNum = IPAdresy[addr]
            maxIP = addr
    print("Adresa uzla s najvacsim poctom odoslanych paketov:\n" + maxIP, "  ->  ", maxNum, "packets")

def doDvojic(myInput):        # rozdeli hex string do dvojic
    i = 0
    novy_string = ""
    length = len(myInput)
    while i < length:
        novy_string += (str(myInput[i:i+2]))
        if i != length-2:           # aby sa nevypisala na koniec medzera
            novy_string += " "
        i += 2
    return novy_string


def formatHexadec(paket):
    i = 0
    byty_v_riadku = 0
    novy_string = ""
    while i < len(paket):
        if byty_v_riadku == 8:
            novy_string += "  "
        if byty_v_riadku == 16:
            byty_v_riadku = 0
            novy_string += "\n"
        novy_string += (str(paket[i:i + 2]))
        novy_string += " "
        i += 2
        byty_v_riadku += 1
    return novy_string


def vypisMacAdries(paket):
    print("Zdrojova MAC Adresa:", doDvojic(paket[12:24]))
    print("Cielova MAC Adresa:", doDvojic(paket[0:12]))


def hexa_to_IP_addr(paket):
    i = 0
    ip_adresa = ""
    packetLength= len(paket)
    while i < packetLength:
        ip_adresa += str( (int(paket[i:i + 2], 16)) )
        if i != packetLength - 2:     # aby sa nevypisala na koniec bodka
            ip_adresa += "."
        i += 2
    return ip_adresa


def getMin(cislo1, cislo2):     # helper func, returns minimum of 2 ints
    min = int(cislo1)
    if min > int(cislo2):
        min = int(cislo2)
    return min


def portHelper(paket, port_begin):
    helper = str(int(paket[port_begin:port_begin + 4], 16))
    return helper


def ipv4_porty(paket, portOffset, type):    # TCP/UDP porty || ICMP code
    minPort = 0
    src_begin = 28 + portOffset*2
    dst_begin = 32 + portOffset*2
    zdrojovyPort = portHelper(paket, src_begin)
    cielovyPort = portHelper(paket, dst_begin)

    if type == "ICMP":
        icmp_type = paket[src_begin:src_begin+2]
        if icmp_type in icmp_codes:
            print(" -",icmp_codes[icmp_type])
        else:
            print(" - Unknown ICMP code")
        return
    print()
    if type == "TCP":
        minPort = getMin(zdrojovyPort, cielovyPort)  # zistenie ktory port je mensi
        minPort = hex(int(minPort)).split('x')[-1]      # decimal -> hexadec
        if minPort in tcp_ports:
            print(tcp_ports[minPort])
    if type == "UDP":
        minPort = getMin(zdrojovyPort, cielovyPort)  # zistenie ktory port je mensi
        minPort = hex(int(minPort)).split('x')[-1]      # decimal -> hexadec
        if minPort in udp_ports:
            print(udp_ports[minPort])

    print("Zdrojovy port:", zdrojovyPort)
    print("Cielovy port:", cielovyPort)


def uloha1az3(packet):         # ulohy 1, 2, 3
    global ramecCislo
    global uloha
    print("----------- Ramec cislo", ramecCislo, "-----------")
    if uloha == "1":        # ak je volana z inej funkcie, cislo sa inkrementuje tam
        ramecCislo += 1

    packetLength = int(len(packet))
    print("Dlzka ramca poskytnuta pcap API - ", packetLength, "B")
    if packetLength < 64:
        print("Dlzka ramca prenasaneho po mediu - 64 B")
    else:
        print("Dlzka ramca prenasaneho po mediu -", packetLength+4, "B")

    packet = packet.hex()

    ethType = int(packet[24:28], 16)       # 12ty až 14ty byte určuju ethType alebo length
    packet_len_802_3 = packet[28:30]       # 802.3 subtypes

    if ethType > 1500:         # Ethernet II
        print("Ethernet II")
        vypisMacAdries(packet)
        if ethType in eth_subprotocols:        # IPv4 or IPv6 or ARP
            print(eth_subprotocols[ethType])
            if eth_subprotocols[ethType] == "IPv4":
                print("Zdrojova IPV4 adresa:", hexa_to_IP_addr(packet[52:60]))
                print("Cielova IPV4 adresa:", hexa_to_IP_addr(packet[60:68]))
                add_src_ipv4_address(hexa_to_IP_addr(packet[52:60]))       # add IPv4 src addr to dict

                odchylkaPortu = int(packet[28]) * int(packet[29])       # IHL, vypocet na ktorom byte je src a dst port

                prType = str(packet[46:48])     # protocol type TCP/UDP/ICMP...
                if prType in ipv4_subprotocols:
                    print(ipv4_subprotocols[prType], end="")
                    if ipv4_subprotocols[prType] == "TCP" or ipv4_subprotocols[prType] == "UDP" or ipv4_subprotocols[prType] == "ICMP":
                        ipv4_porty(packet, odchylkaPortu, ipv4_subprotocols[prType])
        else:
            print("Neznamy protokol")


    elif packet_len_802_3 in frame_types:
        print(frame_types[packet_len_802_3])        # 802.3 Raw or LLC + SNAP
        vypisMacAdries(packet)
        if frame_types[packet_len_802_3] == "802.3 Raw":
            print("IPX")

    else:                              # 802.3 LLC
        print("802.3 LLC")
        vypisMacAdries(packet)
        if packet_len_802_3 in SAPs:
            print(SAPs[packet_len_802_3])


    print(formatHexadec(packet), "\n")


def uloha4a(packet):        #HTTP pakety
    global ramecCislo

    packet = packet.hex()

    ethType = int(packet[24:28], 16)
    if ethType > 1500:
        if ethType in eth_subprotocols and eth_subprotocols[ethType] == "IPv4":        # is IPv4
            portOffset = int(packet[28]) * int(packet[29])
            src_begin = 28 + portOffset * 2
            dst_begin = 32 + portOffset * 2

            zdrojovyPort = portHelper(packet, src_begin)
            cielovyPort = portHelper(packet, dst_begin)

            prType = str(packet[46:48])     # protocol type TCP/UDP/ICMP...
            if prType in ipv4_subprotocols and ipv4_subprotocols[prType] == "TCP":
                minPort = getMin(int(zdrojovyPort), int(cielovyPort))
                minPort = hex(int(minPort)).split('x')[-1]  # decimal -> hexadec
                if minPort in tcp_ports and tcp_ports[minPort] == "http":
                    uloha1az3(unhexlify(packet))

    ramecCislo += 1



def uloha4b(packet):        #HTTPS pakety
    global ramecCislo

    packet = packet.hex()

    ethType = int(packet[24:28], 16)
    if ethType > 1500:
        if ethType in eth_subprotocols and eth_subprotocols[ethType] == "IPv4":  # is IPv4
            portOffset = int(packet[28]) * int(packet[29])
            src_begin = 28 + portOffset * 2
            dst_begin = 32 + portOffset * 2

            zdrojovyPort = portHelper(packet, src_begin)
            cielovyPort = portHelper(packet, dst_begin)

            prType = str(packet[46:48])  # protocol type TCP/UDP/ICMP...
            if prType in ipv4_subprotocols and ipv4_subprotocols[prType] == "TCP":
                minPort = getMin(int(zdrojovyPort), int(cielovyPort))
                minPort = hex(int(minPort)).split('x')[-1]  # decimal -> hexadec
                if minPort in tcp_ports and tcp_ports[minPort] == "https":
                    uloha1az3(unhexlify(packet))

    ramecCislo += 1



def uloha4c(packet):        #TELNET pakety
    global ramecCislo

    packet = packet.hex()

    ethType = int(packet[24:28], 16)
    if ethType > 1500:
        if ethType in eth_subprotocols and eth_subprotocols[ethType] == "IPv4":  # is IPv4
            portOffset = int(packet[28]) * int(packet[29])
            src_begin = 28 + portOffset * 2
            dst_begin = 32 + portOffset * 2

            zdrojovyPort = portHelper(packet, src_begin)
            cielovyPort = portHelper(packet, dst_begin)

            prType = str(packet[46:48])  # protocol type TCP/UDP/ICMP...
            if prType in ipv4_subprotocols and ipv4_subprotocols[prType] == "TCP":
                minPort = getMin(int(zdrojovyPort), int(cielovyPort))
                minPort = hex(int(minPort)).split('x')[-1]  # decimal -> hexadec
                if minPort in tcp_ports and tcp_ports[minPort] == "telnet":     # 4a/b/c/d...
                    uloha1az3(unhexlify(packet))

    ramecCislo += 1



def uloha4d(packet):        #SSH pakety
    global ramecCislo

    packet = packet.hex()

    ethType = int(packet[24:28], 16)
    if ethType > 1500:
        if ethType in eth_subprotocols and eth_subprotocols[ethType] == "IPv4":  # is IPv4
            portOffset = int(packet[28]) * int(packet[29])
            src_begin = 28 + portOffset * 2
            dst_begin = 32 + portOffset * 2

            zdrojovyPort = portHelper(packet, src_begin)
            cielovyPort = portHelper(packet, dst_begin)

            prType = str(packet[46:48])  # protocol type TCP/UDP/ICMP...
            if prType in ipv4_subprotocols and ipv4_subprotocols[prType] == "TCP":
                minPort = getMin(int(zdrojovyPort), int(cielovyPort))
                minPort = hex(int(minPort)).split('x')[-1]  # decimal -> hexadec
                if minPort in tcp_ports and tcp_ports[minPort] == "ssh":
                    uloha1az3(unhexlify(packet))

    ramecCislo += 1



def uloha4e(packet):        #FTP - riadiace pakety
    global ramecCislo

    packet = packet.hex()

    ethType = int(packet[24:28], 16)
    if ethType > 1500:
        if ethType in eth_subprotocols and eth_subprotocols[ethType] == "IPv4":  # is IPv4
            portOffset = int(packet[28]) * int(packet[29])
            src_begin = 28 + portOffset * 2
            dst_begin = 32 + portOffset * 2

            zdrojovyPort = portHelper(packet, src_begin)
            cielovyPort = portHelper(packet, dst_begin)

            prType = str(packet[46:48])  # protocol type TCP/UDP/ICMP...
            if prType in ipv4_subprotocols and ipv4_subprotocols[prType] == "TCP":
                minPort = getMin(int(zdrojovyPort), int(cielovyPort))
                minPort = hex(int(minPort)).split('x')[-1]  # decimal -> hexadec
                if minPort in tcp_ports and tcp_ports[minPort] == "ftp-control":
                    uloha1az3(unhexlify(packet))

    ramecCislo += 1


def uloha4f(packet):        #FTP - datove pakety
    global ramecCislo

    packet = packet.hex()

    ethType = int(packet[24:28], 16)
    if ethType > 1500:
        if ethType in eth_subprotocols and eth_subprotocols[ethType] == "IPv4":  # is IPv4
            portOffset = int(packet[28]) * int(packet[29])
            src_begin = 28 + portOffset * 2
            dst_begin = 32 + portOffset * 2

            zdrojovyPort = portHelper(packet, src_begin)
            cielovyPort = portHelper(packet, dst_begin)

            prType = str(packet[46:48])  # protocol type TCP/UDP/ICMP...
            if prType in ipv4_subprotocols and ipv4_subprotocols[prType] == "TCP":
                minPort = getMin(int(zdrojovyPort), int(cielovyPort))
                minPort = hex(int(minPort)).split('x')[-1]  # decimal -> hexadec
                if minPort in tcp_ports and tcp_ports[minPort] == "ftp-data":
                    uloha1az3(unhexlify(packet))

    ramecCislo += 1


def tftp_spravna_komunikacia(cielovy_port, zdrojovy_port):  # ak sedia porty akt. komunikacie
    try:
        if (tftp_komunikacie[0].dstPort == cielovy_port and tftp_komunikacie[0].srcPort == zdrojovy_port) or (
                    tftp_komunikacie[0].dstPort == zdrojovy_port and tftp_komunikacie[0].srcPort == cielovy_port):
            return True
    except:
        return False


def uloha4g(packet):        #TFTP
    global ramecCislo
    global prve_tftp

    packet = packet.hex()

    ethType = int(packet[24:28], 16)
    if ethType > 1500:
        portOffset = int(packet[28]) * int(packet[29])
        src_begin = 28 + portOffset * 2
        dst_begin = 32 + portOffset * 2

        zdrojovyPort = portHelper(packet, src_begin)
        cielovyPort = portHelper(packet, dst_begin)

        prType = str(packet[46:48])     #protocol type
        if ethType in eth_subprotocols and eth_subprotocols[ethType] == "IPv4":
            if prType in ipv4_subprotocols and ipv4_subprotocols[prType] == "UDP":

                if cielovyPort != "69" and (prve_tftp or tftp_spravna_komunikacia(cielovyPort, zdrojovyPort)):        # ak zacala komunikacia
                    if prve_tftp:
                        tftp_komunikacie[0].dstPort = zdrojovyPort   # nastavim si realny port namiesto 69
                        prve_tftp = 0
                       # print("porty a:", tftp_komunikacie[0].dstPort, "b:", tftp_komunikacie[0].srcPort)

                    uloha1az3(unhexlify(packet))        # vypis ramec

                elif cielovyPort == "69":
                    prve_tftp = 1
                    try:
                        oldSum = tftp_komunikacie[0].pocetKomunikacii       # suma poctu komunikacii TFTP
                    except:
                        oldSum = 0
                    novaKomunikacia = TFTP(zdrojovyPort, cielovyPort)       # zapametam si porty komunikacie
                    novaKomunikacia.pocetKomunikacii = oldSum + 1
                    tftp_komunikacie.insert(0, novaKomunikacia)        # ulozim udaje o komunikacii do global.

                    print("TFTP komunikacia cislo",tftp_komunikacie[0].pocetKomunikacii)
                    uloha1az3(unhexlify(packet))

    ramecCislo += 1

def uloha4h(packet):     # ICMP
    global ramecCislo

    packet = packet.hex()
    ethType = int(packet[24:28], 16)
    if ethType in eth_subprotocols and eth_subprotocols[ethType] == "IPv4":
        offset = int(packet[28]) * int(packet[29])
        code_begin = 28 + offset * 2

        prType = str(packet[46:48])  # protocol type
        if prType in ipv4_subprotocols and ipv4_subprotocols[prType] == "ICMP":
            uloha1az3(unhexlify(packet))


    ramecCislo += 1

def uloha4i(packet):        #ARP
    global ramecCislo
    replyFlag = 0       #if current packet is arp reply to saved arp request

    packet = packet.hex()
    ethType = int(packet[24:28], 16)
    if ethType in eth_subprotocols and eth_subprotocols[ethType] == "ARP":
        zdrojovaMAC = packet[12:24]
        cielovaMAC = packet[0:12]
        opCode = packet[42:44]   # staci z druheho bytu
        arpsrcIP = hexa_to_IP_addr(packet[56:64])
        arpdstIP = hexa_to_IP_addr(packet[76:84])
        if (arpsrcIP == "0.0.0.0") or (arpsrcIP == arpdstIP):       # if ARP probe or announcement, len vypis
            print("ARP - Probe / Announcement / Gratuitous, ramec:")
            uloha1az3(unhexlify(packet))
            return

        print("ARP -", arp_opCode[opCode])
        vypisMacAdries(packet)
        print("Zdrojova IP:",arpsrcIP,"Cielova IP:",arpdstIP)
        if opCode == "01":          #if arp request
            try:
                oldPocet = arp_komunikacie[0].pocetKomunikacii
            except:
                oldPocet = 0
            noveARP = ARP(zdrojovaMAC, cielovaMAC, arpsrcIP, arpdstIP)
            noveARP.pocetKomunikacii = oldPocet
            arp_komunikacie.insert(0, noveARP)
        if opCode == "02":          #if arp reply
            if arpsrcIP == arp_komunikacie[0].dstIP:     #is replying to a request?
                arp_komunikacie[0].pocetKomunikacii += 1      #inkrementuj pocet komunikacii
                replyFlag = 1


        uloha1az3(unhexlify(packet))
        if replyFlag == 1:
            print("^^ Koniec ARP komunikacie cislo", arp_komunikacie[0].pocetKomunikacii, "^^")
            print("-- medzi:", arpsrcIP,"a", arpdstIP, "--")
            print("--------------------------------------")

    ramecCislo += 1


# ----------------ZACIATOK PROGRAMU--------------------
uloha = ""      # globalne definovana kvoli rozhraniu...
def main():
    global uloha

    load_from_files()       # nacita protokoly atd zo suborov do dictionaries

#    pcap = scapy.rdpcap("vzorky_pcap_na_analyzu/trace-1.pcap")  # manualne otvorenie pcap na analyzu

    uloha = "1"        # manualne zadavanie ulohy
    uloha_in = ""

    pcap_in = str(input("Zadajte nazov .pcap suboru (napr. 'trace-14.pcap')\n"))
    otvorSubor = str("vzorky_pcap_na_analyzu/"+pcap_in)
    try:
        pcap = scapy.rdpcap(otvorSubor)
    except:
        print("Chyba, nebol najdeny subor",otvorSubor)
        return
    uloha_in =input("Zadajte cislo ulohy pre vypis, \n'1' pre ulohy 1-3\n'4a' pre ulohu 4a (HTTP)\n'4b' pre ulohu 4b (HTTPS)"
                   "\n'4c' pre ulohu 4c (TELNET)\n'4d' pre ulohu 4d (SSH)\n'4e' pre ulohu 4e (FTP-control)\n'4f' pre ulohu "
                   "4f (FTP-data)\n'4g' pre ulohu 4g (TFTP)\n'4h' pre ulohu 4h (ICMP)\n'4i' pre ulohu 4i (ARP)\n")
    uloha = uloha_in
    # ulohy 1-3
    if uloha == "1":
        for packet in pcap:
            raw_data = scapy.raw(packet)
            uloha1az3(raw_data)
        vypis_src_ipv4()        # bod 3

    # uloha 4a - HTTP komunikacie
    elif uloha == "4a":
        counter = 1
        for packet in pcap:
            #print("Working, ", counter)
            raw_data = scapy.raw(packet)
            uloha4a(raw_data)
            counter += 1

    # uloha 4b - HTTPS komunikacie
    elif uloha == "4b":
        counter = 1
        for packet in pcap:
            #print("Working, ", counter)
            raw_data = scapy.raw(packet)
            uloha4b(raw_data)
            counter += 1
    # uloha 4c - TELNET komunikacie
    elif uloha == "4c":
        counter = 1
        for packet in pcap:
            #print("Working, ", counter)
            raw_data = scapy.raw(packet)
            uloha4c(raw_data)
            counter += 1
    # uloha 4d - SSH komunikacie
    elif uloha == "4d":
        counter = 1
        for packet in pcap:
            raw_data = scapy.raw(packet)
            uloha4d(raw_data)

    # uloha 4e - FTP riadiace komunikacie
    elif uloha == "4e":
        for packet in pcap:
            raw_data = scapy.raw(packet)
            uloha4e(raw_data)

    # uloha 4f - FTP datove komunikacie
    elif uloha == "4f":
        for packet in pcap:
            raw_data = scapy.raw(packet)
            uloha4f(raw_data)

    # uloha 4g - TFTP vsetky ramce komunikacie
    elif uloha == "4g":
        for packet in pcap:
            raw_data = scapy.raw(packet)
            uloha4g(raw_data)
        try:
            print("Zachytene TFTP komunikacie:", tftp_komunikacie[0].pocetKomunikacii)
        except:
            print("Neboli zachytene ziadne TFTP komunikacie v tomto subore")

    # uloha 4h - ICMP ramce
    elif uloha == "4h":
        for packet in pcap:
            raw_data = scapy.raw(packet)
            uloha4h(raw_data)

    # uloha 4i - ARP dvojice
    elif uloha == "4i":
        for packet in pcap:
            raw_data = scapy.raw(packet)
            uloha4i(raw_data)
        try:
            print("Zachytene ARP dvojice:", arp_komunikacie[0].pocetKomunikacii)
        except:
            print("Neboli zachytene ziadne ARP komunikacie v tomto subore")

    elif uloha_in != "" and uloha == uloha_in:
        print("Zly vstup, program skonci")
        return


main()

#sys.stdout.close()