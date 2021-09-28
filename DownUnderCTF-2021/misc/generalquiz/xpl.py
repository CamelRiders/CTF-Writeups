# Author: ghsi10

from pwn import *
from urllib.parse import unquote
from base64 import b64decode, b64encode, encode
from codecs import encode

p = remote("pwn-2021.duc.tf", 31905)

p.sendlineafter(b"...", b"")
p.sendlineafter(b"1+1=?", b"2")

p.recvuntil(b"(base 10): ")
p.sendline(str(int(p.recvline()[2:-1],16)).encode())

p.recvuntil(b"letter: ")
p.sendline(str(chr(int(p.recvline()[:-1],16))).encode())


p.recvuntil(b"symbols: ")
p.sendline(unquote(p.recvline()[:-1].decode()).encode())

p.recvuntil(b"plaintext: ")
p.sendline(b64decode(p.recvline()[:-1]))

p.recvuntil(b"Base64: ")
p.sendline(b64encode(p.recvline()[:-1]))

p.recvuntil(b"plaintext: ")
p.sendline(encode(p.recvline()[:-1].decode(),"rot_13").encode())

p.recvuntil(b"equilavent: ")
p.sendline(encode(p.recvline()[:-1].decode(),"rot_13").encode())

p.recvuntil(b"(base 10): ")
p.sendline(str(int(p.recvline()[2:-1],2)).encode())

p.recvuntil(b"equivalent: ")
p.sendline(str(bin(int(p.recvline()[:-1],10))).encode())


p.sendlineafter(b"universe?", b"DUCTF")

p.interactive()