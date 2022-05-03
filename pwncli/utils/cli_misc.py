
import os
from threading import Lock
import time
from pwncli.cli import gift
from .misc import get_callframe_info, log2_ex, errlog_exit, log_code_base_addr, log_libc_base_addr, \
    one_gadget_binary, get_segment_base_addr_by_proc_maps, recv_libc_addr, \
    get_flag_when_get_shell
from pwn import flat, asm
from .ropperbox import RopperBox, RopperArchType

__all__ = [
    "stop",
    "S",
    "get_current_one_gadget",
    "get_current_codebase_addr",
    "get_current_libcbase_addr",
    "get_current_stackbase_addr",
    "get_current_heapbase_addr",
    "kill_current_gdb",
    "send_signal2current_gdbprocess",
    "execute_cmd_in_current_gdb",
    "set_current_pie_breakpoints",
    "tele_current_pie_content",
    "recv_current_libc_addr",
    "get_current_flag_when_get_shell",
    "set_current_libc_base", 
    "set_current_libc_base_and_log",
    "set_current_code_base",
    "set_current_code_base_and_log",
    "s", "sl", "sa", "sla", "ru", "rl","rs",
    "rls", "rlc", "ra", "rr", "r", "rn", "ia", "ic",
    "CurrentGadgets"
    ]

def stop(enable=True):
    """Stop the program and print the caller's info

    Args:
        enable (bool, optional): if it's False, this function will return directly. Defaults to True.
    """
    if not enable:
        return

    if gift.get('no_stop', None):
        return

    func_name = ''
    module_name = ''
    lineno, pid = -1, -1
    try:
        # try to get file line number
        module_name, func_name, lineno = get_callframe_info(depth=3)
    except:
        lineno = -1

    # try to get pid
    if gift.get('io', None) and gift.get('debug', None):
        pid = gift['io'].proc.pid

    msg = 'Stop'
    if lineno != -1:
        msg += ' at module: {}  function: {}  line: {}'.format(module_name, func_name, lineno)
    if pid != -1:
        msg += '  local pid: {}'.format(pid)
    log2_ex(msg)
    input(" Press any key to continue......")

S = stop

#----------------------------useful function-------------------------
def get_current_one_gadget(libc_base=0, more=False):
    """Get current filename's all one_gadget.

    """
    if not gift.get('filename', None):
        errlog_exit("Cannot get_current_one_gadget, filename is None!")
    res = [x + libc_base for x in one_gadget_binary(gift['filename'], more)]
    log2_ex("Get one_gadget: {}".format([hex(x) for x in res]))
    return res

_cache_segment_base_addr = None
def __get_current_segment_base_addr(use_cache=True) -> dict:
    global _cache_segment_base_addr
    """Get current process's segments' base address."""
    if use_cache and _cache_segment_base_addr is not None:
        return _cache_segment_base_addr
    # try to get pid
    if gift.get('io', None) and gift.get('debug', None):
        pid = gift['io'].proc.pid
        filename = gift.get('filename', None)
        if filename is not None:
            filename = os.path.split(os.path.abspath(filename))[1]
        _cache_segment_base_addr = get_segment_base_addr_by_proc_maps(pid, filename)
        return _cache_segment_base_addr
    else:
        errlog_exit("get_current_segment_base_addr failed! No pid!")


def get_current_codebase_addr(use_cache=True) -> int:
    r = __get_current_segment_base_addr(use_cache)
    return r['code']


def get_current_libcbase_addr(use_cache=True) -> int:
    r = __get_current_segment_base_addr(use_cache)
    return r['libc']


def get_current_stackbase_addr(use_cache=True) -> int:
    r = __get_current_segment_base_addr(use_cache)
    return r['stack']


def get_current_heapbase_addr(use_cache=True) -> int:
    r = __get_current_segment_base_addr(use_cache)
    return r['heap']


#----------------------------gdb related-------------------------
from pwncli.utils.gdb_helper import *

def _check_current_gdb():
    if not gift.get('gdb_pid', None):
        errlog_exit("cannot get gdb_obj, you don't launch gdb?")


def kill_current_gdb():
    """Kill current gdb process."""
    _check_current_gdb()
    try:
        kill_gdb(gift['gdb_obj'])
    except:
        kill_gdb(gift['gdb_pid'])


def send_signal2current_gdbprocess(sig_val:int=2):
    _check_current_gdb()
    os.system("kill -{} {}".format(sig_val, gift['gdb_pid']))
    time.sleep(0.2)


def execute_cmd_in_current_gdb(cmd:str):
    """Execute commands in current gdb, split commands by ';' or \\n."""
    _check_current_gdb()
    execute_cmd_in_gdb(gift["gdb_obj"], cmd)
    

def set_current_pie_breakpoints(offset:int):
    """Set breakpoints by offset when binary's PIE enabled. Only support for `pwndbg'."""
    _check_current_gdb()
    set_pie_breakpoints(gift["gdb_obj"], offset)


def tele_current_pie_content(offset:int, number=10):
    """Telescope current content by offset when binary's PIE enabled. Only support for 'pwndbg'."""
    tele_pie_content(gift["gdb_obj"], offset, number)



#-----------------other------------------------

def recv_current_libc_addr(offset:int=0):
    if not gift.get("elf", None):
        errlog_exit("Can not get current libc addr because of no elf.")
    if not gift.get('io', None):
        errlog_exit("Can not get current libc addr because of no io.")
    
    return recv_libc_addr(gift['io'], bits=gift['elf'].bits, offset=offset)


def get_current_flag_when_get_shell(use_cat=True, start_str="flag{"):
    if not gift.get('io', None):
        errlog_exit("Can not get current libc addr because of no io.")
    get_flag_when_get_shell(gift['io'], use_cat, start_str)


def _innner_set_current_base(addr: int, offset: str or int, name: str) -> int:
    if not gift[name]:
        errlog_exit("No {} here.".format(name))
    if gift[name].address != 0:
        errlog_exit("The address of current {} is not 0.".format(name))
    if isinstance(offset, str):
        offset = gift[name].sym[offset]
    
    base_addr = addr - offset
    gift[name].address = base_addr
    return base_addr



def set_current_libc_base(addr: int, offset: str or int = 0) -> int:
    """set_current_libc_base

    Args:
        addr (int): The address you get
        offset (str or int): offset or func name in current libc

    Returns:
        int: libc base addr
    """
    return _innner_set_current_base(addr, offset, 'libc')


def set_current_libc_base_and_log(addr: int, offset: int or str=0):
    """set_current_libc_base and log

    Args:
        addr (int): The address you get
        offset (str or int): offset or func name in current libc

    Returns:
        int: libc base addr
    """
    res = set_current_libc_base(addr, offset)
    log_libc_base_addr(res)
    return res

def set_current_code_base(addr: int, offset: str or int = 0) -> int:
    """set_current_code_base

    Args:
        addr (int): The address you get
        offset (str or int): offset or func name in current elf

    Returns:
        int: elf base addr
    """
    return _innner_set_current_base(addr, offset, 'elf')


def set_current_code_base_and_log(addr: int, offset: int or str = 0):
    """set_current_code_base and log

    Args:
        addr (int): The address you get
        offset (str or int): offset or func name in current elf

    Returns:
        int: elf base addr
    """
    res = set_current_code_base(addr, offset)
    log_code_base_addr(res)
    return res

#-----------------------------io------------------------
def s(data):
    """send"""
    io = gift.get("io", None)
    if io:
        io.send(data)

def sl(data):
    """sendline"""
    io = gift.get("io", None)
    if io:
        io.sendline(data)

def sa(delim, data):
    """sendafter"""
    io = gift.get("io", None)
    if io:
        io.sendafter(delim, data)

def sla(delim, data):
    """sendlineafter"""
    io = gift.get("io", None)
    if io:
        io.sendlineafter(delim, data)

def ru(delim) -> bytes:
    """recvuntil"""
    io = gift.get("io", None)
    if io:
        return io.recvuntil(delim)

def rl() -> bytes:
    """recvline"""
    io = gift.get("io", None)
    if io:
        return io.recvline()

def rs(n) -> list:
    """recvlines"""
    io = gift.get("io", None)
    if io:
        return io.recvlines(n)

def rls(delims) -> bytes:
    """recvline_startswith"""
    io = gift.get("io", None)
    if io:
        return io.recvline_startswith(delims)

def rlc(delims) -> bytes:
    """recvline_contains"""
    io = gift.get("io", None)
    if io:
        return io.recvline_contains(delims)

def ra(timeout=5) -> bytes:
    """recvall"""
    io = gift.get("io", None)
    if io:
        return io.recvall(timeout)

def rr(regex) -> bytes:
    """recvregex"""
    io = gift.get("io", None)
    if io:
        return io.recvregex(regex)

def r() -> bytes:
    """recv"""
    io = gift.get("io", None)
    if io:
        return io.recv()

def rn(n) -> bytes:
    """recvn"""
    io = gift.get("io", None)
    if io:
        return io.recvn(n)

def ia():
    """interactive"""
    io = gift.get("io", None)
    if io:
        io.interactive()

def ic():
    """close"""
    io = gift.get("io", None)
    if io:
        io.close()

# ----------------------------------gadget----------------

class CurrentGadgets:
    __internal_libcbox = None
    __elf = None
    __libc = None
    __arch = None
    __find_in_elf = True
    __find_in_libc = True
    __loaded = False

    _mutex = Lock()

    @staticmethod
    def set_find_area(find_in_elf=True, find_in_libc=False):
        CurrentGadgets.__find_in_elf = find_in_elf
        CurrentGadgets.__find_in_libc = find_in_libc

    @staticmethod
    def _initial_ropperbox() -> bool:
        """Get gadget from current elf and libc"""
        if CurrentGadgets._mutex.acquire(blocking=True):
            CurrentGadgets._mutex.locked()
        
        if CurrentGadgets.__loaded:
            CurrentGadgets._mutex.release()
            return True

        elf = gift.get('elf')
        libc = gift.get('libc')
        CurrentGadgets.__elf = elf
        CurrentGadgets.__libc = libc
        __arch_mapping = {
            "i386": RopperArchType.x86,
            "amd64": RopperArchType.x86_64
        }

        if not elf and not libc:
            log2_ex("Cannot find gadget, no elf and no libc now.")
            CurrentGadgets._mutex.release()
            return False

        if not CurrentGadgets.__find_in_elf and not CurrentGadgets.__find_in_libc:
            log2_ex("Have closed both elf finder and libc finder.")
            CurrentGadgets._mutex.release()
            return False

        CurrentGadgets.__internal_libcbox = RopperBox()

        res = False
        if elf and CurrentGadgets.__find_in_elf:
            if elf.arch not in __arch_mapping:
                log2_ex("Unsupported arch, only for i386 and amd64.")
            else:
                CurrentGadgets.__arch = elf.arch
                CurrentGadgets.__internal_libcbox.add_file("elf", elf.path, __arch_mapping[elf.arch])
                res = True
        if libc and CurrentGadgets.__find_in_libc:
            if libc.arch not in __arch_mapping:
                log2_ex("Unsupported arch, only for i386 and amd64..")
            else:
                CurrentGadgets.__arch = libc.arch
                CurrentGadgets.__internal_libcbox.add_file("libc", libc.path, __arch_mapping[elf.arch])
                res = True
        
        CurrentGadgets.__loaded = res
        CurrentGadgets._mutex.release()
        return res

    @staticmethod
    def reset():
        CurrentGadgets.__internal_libcbox = None
        CurrentGadgets.__elf = None
        CurrentGadgets.__libc = None
        CurrentGadgets.__arch = None
        CurrentGadgets.__find_in_elf = True
        CurrentGadgets.__find_in_libc = True
        CurrentGadgets.__loaded = False
        CurrentGadgets._initial_ropperbox()

    @staticmethod
    def _internal_find(func_name):
        if not CurrentGadgets._initial_ropperbox(): 
            return 0
        func = getattr(CurrentGadgets.__internal_libcbox, func_name)
        try:
            res = func('elf')
            if CurrentGadgets.__elf.pie:
                res += CurrentGadgets.__elf.address
            return res
        except:
            res = func('libc')
            if CurrentGadgets.__libc.pie:
                res += CurrentGadgets.__libc.address
            return res

    @staticmethod
    def find_gadget(find : str, find_type='asm', get_list=False) -> int:
        """ type: asm / opcode / string """
        if not CurrentGadgets._initial_ropperbox(): 
            return 0
        if find_type == "asm":
            find = asm(find).hex()
            func = getattr(CurrentGadgets.__internal_libcbox, "search_opcode")
        elif find_type == "opcode":
            func = getattr(CurrentGadgets.__internal_libcbox, "search_opcode")
        elif find_type == "string":
            func = getattr(CurrentGadgets.__internal_libcbox, "search_string")
        else:
            errlog_exit("Unsupported find_type, only: asm / opcode / string.")
        try:
            res = func(find ,'elf', get_list)
            if CurrentGadgets.__elf.pie:
                if get_list:
                    return [i + CurrentGadgets.__elf.address for i in res]
                else:
                    return CurrentGadgets.__elf.address + res
        except:
            res = func(find ,'libc', get_list)
            if CurrentGadgets.__libc.pie:
                if get_list:
                    return [i + CurrentGadgets.__libc.address for i in res]
                else:
                    return CurrentGadgets.__libc.address + res 

    @staticmethod
    def syscall() -> int:
        """syscall"""
        if CurrentGadgets.__arch == "i386":
            return CurrentGadgets._internal_find('get_int80')
        elif CurrentGadgets.__arch == "amd64":
            return CurrentGadgets._internal_find('get_syscall')

    @staticmethod
    def syscall_ret() -> int:
        """syscall; ret"""
        if CurrentGadgets.__arch == "i386":
            return CurrentGadgets._internal_find('get_int80_ret')
        elif CurrentGadgets.__arch == "amd64":
            return CurrentGadgets._internal_find('get_syscall_ret')

    @staticmethod
    def ret() -> int:
        """ret"""
        return CurrentGadgets._internal_find('get_ret')

    @staticmethod
    def pop_rdi_ret() -> int:
        """pop rdi; ret"""
        return CurrentGadgets._internal_find('get_pop_rdi_ret')

    @staticmethod
    def pop_rsi_ret() -> int:
        """pop rsi; ret"""
        return CurrentGadgets._internal_find('get_pop_rsi_ret')
    
    @staticmethod
    def pop_rdx_ret() -> int:
        """pop rdx; ret"""
        return CurrentGadgets._internal_find('get_pop_rdx_ret')

    @staticmethod
    def pop_rax_ret() -> int:
        """pop rax; ret"""
        return CurrentGadgets._internal_find('get_pop_rax_ret')

    @staticmethod
    def pop_rbx_ret() -> int:
        """pop rbx; ret"""
        return CurrentGadgets._internal_find('get_pop_rbx_ret')

    @staticmethod
    def pop_rcx_ret() -> int:
        """pop rcx; ret"""
        return CurrentGadgets._internal_find('get_pop_rcx_ret')

    @staticmethod
    def pop_rbp_ret() -> int:
        """pop rbp; ret"""
        return CurrentGadgets._internal_find('get_pop_rbp_ret')

    @staticmethod
    def pop_rsp_ret() -> int:
        """pop rsp; ret"""
        return CurrentGadgets._internal_find('get_pop_rsp_ret')

    @staticmethod
    def pop_rsi_r15_ret() -> int:
        """pop rsp; ret"""
        return CurrentGadgets._internal_find('get_pop_rsi_r15_ret')

    @staticmethod
    def magic_gadget() -> int:
        """add dword ptr [rbp - 0x3d], ebx"""
        assert CurrentGadgets.__arch == "amd64", "only for amd64"
        return CurrentGadgets._internal_find('get_magic_gadget')

    @staticmethod
    def leave_ret() -> int:
        """leave; ret"""
        return CurrentGadgets._internal_find('get_leave_ret')

    @staticmethod
    def bin_sh() -> int:
        """/bin/sh"""
        return CurrentGadgets._internal_find('get_bin_sh')

    @staticmethod
    def sh() -> int:
        """sh"""
        return CurrentGadgets._internal_find('get_sh')

    @staticmethod
    def execve_chain(bin_sh_addr=None) -> bytes:
        CurrentGadgets._initial_ropperbox()
        if CurrentGadgets.__arch == "i386":
            layout = [
                CurrentGadgets.pop_rbx_ret(),
                bin_sh_addr or CurrentGadgets.bin_sh(),
                CurrentGadgets.pop_rcx_ret(),
                0,
                CurrentGadgets.pop_rdx_ret(),
                0,
                CurrentGadgets.pop_rax_ret(),
                0xb,
                CurrentGadgets.syscall()
            ]
        elif CurrentGadgets.__arch == "amd64":
            layout = [
                CurrentGadgets.pop_rdi_ret(),
                bin_sh_addr or CurrentGadgets.bin_sh(),
                CurrentGadgets.pop_rsi_ret(),
                0,
                CurrentGadgets.pop_rdx_ret(),
                0,
                CurrentGadgets.pop_rax_ret(),
                0x3b,
                CurrentGadgets.syscall()
            ]
        else:
            errlog_exit("Unsupported arch: {}".format(CurrentGadgets.__arch))
        
        return flat(layout)

    @staticmethod
    def mprotect_chain(va, length=0x1000, prog=7) -> bytes:
        CurrentGadgets._initial_ropperbox()
        if CurrentGadgets.__arch == "i386":
            layout = [
                CurrentGadgets.pop_rbx_ret(),
                va,
                CurrentGadgets.pop_rcx_ret(),
                length,
                CurrentGadgets.pop_rdx_ret(),
                prog,
                CurrentGadgets.pop_rax_ret(),
                125,
                CurrentGadgets.syscall()
            ]
        elif CurrentGadgets.__arch == "amd64":
            layout = [
                CurrentGadgets.pop_rdi_ret(),
                va,
                CurrentGadgets.pop_rsi_ret(),
                length,
                CurrentGadgets.pop_rdx_ret(),
                prog,
                CurrentGadgets.pop_rax_ret(),
                10,
                CurrentGadgets.syscall()
            ]
        else:
            errlog_exit("Unsupported arch: {}".format(CurrentGadgets.__arch))
        
        return flat(layout)