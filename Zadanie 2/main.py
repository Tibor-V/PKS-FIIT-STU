import socket
import time
import math
import os
import binascii


def client_init():  # sender
    UDP_IP = "127.0.0.1"
    UDP_PORT = 5005
    MSG = ""
    MSG_TYPE = -1
    msg_details = ()    # nazov suboru a type
    init_request = "0"
    fragment_size = 1000

    UDP_IP = input("Zadajte server IP: ")
    UDP_PORT = int(input("Zadajte server port: "))
    fragment_size = -1
    while not (fragment_size >= 2 and fragment_size <= 1465):
        fragment_size = int(input("Zadajte velkost fragmentu (2 - 1465): "))

    while MSG_TYPE != "1" and MSG_TYPE != "2":
        print("Ak chcete poslat SPRAVU, vlozte '1', ak chcete poslat SUBOR, vlozte '2'")
        MSG_TYPE = str(input("Zvoleny typ: "))
    if MSG_TYPE == "1":
        MSG = str(input("Napiste spravu: "))
        msg_details = (None, MSG_TYPE)     # sprava nema cestu, typ
    elif MSG_TYPE == "2":
        cesta = str(input("Zadajte cestu k súboru (tvar D:/cesta/k/suboru/ahoj.txt): "))
        MSG = read_subor(cesta)
        msg_details = (cesta, MSG_TYPE)      # nazov suboru, typ

    sock = socket.socket(socket.AF_INET,  # Internet
                         socket.SOCK_DGRAM)  # UDP
    sock.sendto(init_request.encode(), (UDP_IP, UDP_PORT))

    print("waiting for confirmation...")
    while True:
        data, addr = sock.recvfrom(1500)
        data = data.decode()
        if data == "0":  # initialization accepted!
            print("Accepted confirmation for init by client")
            msg = MSG
            client_send_message(sock, addr, fragment_size, msg, msg_details)
            break


def get_nazov_suboru(cesta):
    splitt = cesta.split('/')
    return splitt[-1]


def read_subor(nazov_suboru):
    file = open(nazov_suboru, "rb")
    print("Reading data from file...", end="")
    byte = file.read(1024)
    data = byte
    while byte:
        byte = file.read(1024)
        data = data + byte
    print(" done!")
    return data


def fragmentation(message, fragmentSize):
    velkost = len(message)
    parts = [message[i:i + fragmentSize] for i in range(0, velkost, fragmentSize)]
    return parts


def encoder(string):
    try:
        string = string.encode()
    except:
        string = string
    return string


def getHeader(typ, velkost, pocet_fragmentov, crc):
    typ = int(typ).to_bytes(1, byteorder='big')
    velkost = int(velkost).to_bytes(2, byteorder='big')
    pocet_fragmentov = int(pocet_fragmentov).to_bytes(2, byteorder='big')
    crc = int(crc).to_bytes(2, byteorder='big')
    header = typ + velkost + pocet_fragmentov + crc
    return header


def getCRC(data):           # spocita crc16 z datovej casti
    try:
        data = data.encode()
    except:
        data = data
    crc = binascii.crc_hqx(data, 0)
    return crc


def corrupt_fragment(fragment):
    byte = fragment[0] ^ 0b0000001
    new_fragment = int(byte).to_bytes(1, byteorder='big')
    for piece in fragment[1:]:
        new_fragment += int(piece).to_bytes(1, byteorder='big')
    return new_fragment


def client_send_message(socket, addr, fragmentSize, message, msg_details):
    # inicializacia prebehla, vytvori sa hlavicka a appendne sa k nej sprava

    TARGET_IP = addr[0]
    TARGET_PORT = addr[1]
    packet_fragments = []
    fragment_index = 1      # cislo posielaneho fragmentu
    message = encoder(message)

    typ = msg_details[1]  # prenos dat, sprava = "1", subor = "2"
    velkost = len(message)
    pocet_fragmentov = math.floor(velkost / fragmentSize) + 1

    if typ == "2":      # ak posielame subor, prvy paket bude nazov suboru
        nazov_suboru = get_nazov_suboru(msg_details[0])
        print("Absolutna cesta k posielanemu suboru:",os.path.abspath(msg_details[0]))
        packet_fragments.append(nazov_suboru.encode())    # nazov suboru
        pocet_fragmentov += 1

    if velkost > fragmentSize:
        packet_fragments.extend(fragmentation(message, fragmentSize))  # rozdelenie na fragmenty (uz encoded)
    else:
        packet_fragments.append(message)

    for fragment in packet_fragments:  # posle kazdy fragment samostatne, pocka na ACK
        # if fragment_index == 2:     # ak klient takto prestane posielat, triggerne sa timeout
        #    exit()
        velkost = len(fragment)
        hlavicka = getHeader(typ, velkost, pocet_fragmentov, getCRC(fragment))
        msg = hlavicka + fragment

        #if (typ == "2" and (fragment_index >= 2 and fragment_index % 2 == 0)) or (typ == "1" and fragment_index == 1):      # vnesenie chyby
        #    print("\ncorrupting fragment",fragment_index)
        #    fragment = corrupt_fragment(fragment)
        #    corrupted = hlavicka + fragment
        #    socket.sendto(corrupted, (TARGET_IP, TARGET_PORT))
        #else:
        socket.sendto(msg, (TARGET_IP, TARGET_PORT))
        print("\nOdoslany fragment cislo",fragment_index,"/",pocet_fragmentov)
        print("Velkost fragmentu (bez hlavicky): ",velkost,"B")
        print("Cakanie na ACK... ", end="")
        while True:
            data, addrDUMP = socket.recvfrom(1500)
            data = data.decode()
            if data == "3":  # prislo ACK, poslem dalsi segment
                print("ACK!")
                break
            elif data == "4":  # send again
                print("NACK\nPrijata ziadost o znovu-poslanie fragmentu, posielam... ", end="")
                socket.sendto(msg, (TARGET_IP, TARGET_PORT))
                continue
        fragment_index += 1
    print("\nVsetky fragmenty spracovane klientom")
    print("\n\n")


def server_init():  # receiver
    UDP_IP = "127.0.0.1"
    UDP_PORT = 5005

    UDP_PORT = int(input("Zadajte server port: "))

    sock = socket.socket(socket.AF_INET,  # Internet
                         socket.SOCK_DGRAM)  # UDP
    sock.bind((UDP_IP, UDP_PORT))
    print("Server caka na spojenie...\n")
    while True:
        data, addr = sock.recvfrom(1500)
        data = data.decode()
        if data == "0":
            print("Server received initialization request")
            print("from address:", addr)
            sock.sendto("0".encode(), (UDP_IP, addr[1]))
            time.sleep(0.1)
            print("ACK for init sent to client!")
            server_receive_message(sock, addr)
            break


def unpack_header(data):        # header je na 0.-7. B
    typ = int.from_bytes(data[:1], byteorder='big')                 # 0. index (1B)
    velkost = int.from_bytes(data[1:3], byteorder='big')            # 1., 2. index (2B)
    pocet_fragmentov = int.from_bytes(data[3:5], byteorder='big')   # 3., 4. index (2B)
    crc = int.from_bytes(data[5:7], byteorder='big')                # 5., 6. index (2B)

    return typ, velkost, pocet_fragmentov, crc


def save_subor(nazov, data):
    nazov = "receiving_files/" + nazov
    abs_path = os.path.abspath(nazov)
    file = open(abs_path, "wb")
    file.write(data)
    file.close()
    return abs_path


def server_receive_message(socket, addr):
    sprava = "".encode()
    prijate_fragmenty = 0
    nazov_suboru = ""
    print()

    try:
        while True:
            socket.settimeout(10)
            data, addrDUMP = socket.recvfrom(1500)
            socket.settimeout(None)
            typ, velkost, pocet_fragmentov, crc = unpack_header(data)

            crc_check = getCRC(data[7:])
            if crc_check != crc:
                print("Chybny fragment cislo",prijate_fragmenty+1,"registrovany, posielam NACK!")
                socket.sendto("4".encode(), addr)  # poskodene data, send again please
                continue
            if str(typ) == "2" and prijate_fragmenty == 0:          # subor, prvy fragment je nazov
                print("Registrovany subor, ukladam nazov")
                nazov_suboru = data[7:].decode()
            else:
                sprava = sprava + data[7:]              # else citame data suboru / spravy
            prijate_fragmenty += 1
            print("Prijaty fragment cislo",prijate_fragmenty,"/",pocet_fragmentov)
            print("Velkost fragmentu (bez hlavicky):",velkost,"B\n")

            socket.sendto("3".encode(), addr)  # send ACK
            if prijate_fragmenty == pocet_fragmentov:  # posledny fragment bol prijaty
                break
            continue
    except TimeoutError:
        print("Vyprsal timeout period, server ukoncuje spojenie")
    if nazov_suboru != "":          # prijali sme subor, nie spravu
        print("Nazov suboru:", nazov_suboru)
        path = save_subor(nazov_suboru, sprava)
        print("\tcesta k ulozenemu suboru:", path)
    else:
        print("Na server prisla sprava:", sprava, "\ndlzka spravy: ", len(sprava))
        print("Dekodovana sprava:", sprava.decode())
    print("\n\n")


def zaciatok():
    # pouzivatelske rozhranie
    while True:
        var = -1
        # odtialto sa bude pokracovat po prenose - automaticka moznost na vymenu roli
        print("----------ZACIATOK VYBERU ROLE----------")
        print("Ak chcete skoncit program, vlozte '0'")
        print("Ak chcete program spustit ako CLIENT, vlozte '1'")
        print("Ak chcete program spustit ako SERVER, vlozte '2'")
        while var != "0" and var != "1" and var != "2":
            var = input("Vasa volba: ")
        if var == "0":
            print("---Program sa ukoncuje---")
            exit()
        elif var == "1":
            print("Zvolili ste si client")
            client_init()
        elif var == "2":
            print("Zvolili ste si server")
            server_init()

print("---------------UDP Komunikator---------------")
zaciatok()


