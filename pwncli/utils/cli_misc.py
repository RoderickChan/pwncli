
import functools
import os
from threading import Lock, Thread
import time
from pwncli.cli import gift
from .misc import get_callframe_info, log_ex, log2_ex, errlog_exit, log_code_base_addr, log_libc_base_addr, \
    one_gadget_binary, one_gadget, get_segment_base_addr_by_proc_maps, recv_libc_addr, \
    get_flag_when_get_shell, ldd_get_libc_path
from pwn import flat, asm, ELF, process, remote
from .ropperbox import RopperBox, RopperArchType
from .decorates import deprecated

__all__ = [
    "stop",
    "S",
    "get_current_one_gadget",
    "get_current_one_gadget_from_file",
    "get_current_one_gadget_from_libc",
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
    "set_remote_libc",
    "copy_current_io",
    "s", "sl", "sa", "sla", "st", "slt", "ru", "rl","rs",
    "rls", "rlc", "rle", "ra", "rr", "r", "rn", "ia", "ic", "cr",
    "CurrentGadgets", "load_currentgadgets_background"
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
def get_current_one_gadget_from_file(libc_base=0, more=False):
    """Get current filename's all one_gadget.

    """
    if not gift.get('filename', None):
        errlog_exit("Cannot get_current_one_gadget, filename is None!")
    res = [x + libc_base for x in one_gadget_binary(gift['filename'], more)]
    log_ex("Get one_gadget: {} from {}".format([hex(x) for x in res], ldd_get_libc_path(gift['filename'])))
    return res

@deprecated("please use 'get_current_one_gadget_from_file' and 'get_current_one_gadget_from_libc' instead.")
def get_current_one_gadget(libc_base=0, more=False):
    get_current_one_gadget_from_file(libc_base, more)
    

def get_current_one_gadget_from_libc(more=False):
    """Get current all one_gadget from libc

    """
    if not gift.get('libc', None):
        errlog_exit("Cannot get_current_one_gadget_from_libc, libc is None!")
    res = [x + gift['libc'].address for x in one_gadget(gift['libc'].path, more)]
    log_ex("Get one_gadget: {} from {}".format([hex(x) for x in res], gift['libc'].path))
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


@deprecated
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


def set_remote_libc(libc_so_path: str) -> ELF:
    if not gift.get('remote'):
        return
    if not gift.get('io', None):
        errlog_exit("Can not set remote libc because of no io.")
    if os.path.exists(libc_so_path) and os.path.isfile(libc_so_path):
        gift['libc'] = ELF(libc_so_path, checksec=False)
        gift['libc'].address = 0
        return gift['libc']
    else:
        errlog_exit("libc_so_path not exists!")


def copy_current_io():
    """Only used for debug command"""
    io = None
    if gift.get('debug'):
        io = process(gift.filename)
    elif gift.get('remote'):
        io = remote(gift.io, gift.port)
    else:
        raise RuntimeError()
    return io

#-----------------------------io------------------------
def s(*args, **kwargs):
    """send"""
    io = gift.get("io", None)
    if io:
        io.send(*args, **kwargs)

def sl(*args, **kwargs):
    """sendline"""
    io = gift.get("io", None)
    if io:
        io.sendline(*args, **kwargs)

def sa(*args, **kwargs):
    """sendafter"""
    io = gift.get("io", None)
    if io:
        io.sendafter(*args, **kwargs)

def sla(*args, **kwargs):
    """sendlineafter"""
    io = gift.get("io", None)
    if io:
        io.sendlineafter(*args, **kwargs)

def st(*args, **kwargs):
    """sendthen"""
    io = gift.get("io", None)
    if io:
        io.sendthen(*args, **kwargs)

def slt(*args, **kwargs):
    """sendlinethen"""
    io = gift.get("io", None)
    if io:
        io.sendlinethen(*args, **kwargs)


def ru(*args, **kwargs) -> bytes:
    """recvuntil"""
    io = gift.get("io", None)
    if io:
        return io.recvuntil(*args, **kwargs)

def rl() -> bytes:
    """recvline"""
    io = gift.get("io", None)
    if io:
        return io.recvline()

def rs(*args, **kwargs) -> list:
    """recvlines"""
    io = gift.get("io", None)
    if io:
        return io.recvlines(*args, **kwargs)

def rls(*args, **kwargs) -> bytes:
    """recvline_startswith"""
    io = gift.get("io", None)
    if io:
        return io.recvline_startswith(*args, **kwargs)

def rle(*args, **kwargs) -> bytes:
    """recvline_endswith"""
    io = gift.get("io", None)
    if io:
        return io.recvline_endswith(*args, **kwargs)

def rlc(*args, **kwargs) -> bytes:
    """recvline_contains"""
    io = gift.get("io", None)
    if io:
        return io.recvline_contains(*args, **kwargs)

def ra(timeout=5) -> bytes:
    """recvall"""
    io = gift.get("io", None)
    if io:
        return io.recvall(timeout)

def rr(*args, **kwargs) -> bytes:
    """recvregex"""
    io = gift.get("io", None)
    if io:
        return io.recvregex(*args, **kwargs)

def r(*args, **kwargs) -> bytes:
    """recv"""
    io = gift.get("io", None)
    if io:
        return io.recv(*args, **kwargs)

def rn(*args, **kwargs) -> bytes:
    """recvn"""
    io = gift.get("io", None)
    if io:
        return io.recvn(*args, **kwargs)

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

def cr() -> bool:
    """can_recv"""
    io = gift.get("io", None)
    if io:
        return io.can_recv()

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
    def set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False):
        CurrentGadgets.__find_in_elf = find_in_elf
        CurrentGadgets.__find_in_libc = find_in_libc
        if do_initial:
            CurrentGadgets._initial_ropperbox()

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
        if CurrentGadgets.__find_in_elf:
            try:
                res = func('elf')
                if CurrentGadgets.__elf.pie:
                    res += CurrentGadgets.__elf.address
                return res
            except:
                pass
        
        if CurrentGadgets.__find_in_libc:
            res = func('libc')
            if CurrentGadgets.__libc.pie:
                res += CurrentGadgets.__libc.address
            return res
        
        if not CurrentGadgets.__find_in_elf and not CurrentGadgets.__find_in_libc:
            errlog_exit("Have closed both elf finder and libc finder.")
        errlog_exit("Cannot find gadget using '{}'.".format(func_name))


    @staticmethod
    @functools.lru_cache(maxsize=128, typed=True)
    def find_gadget(find_str : str, find_type='asm', get_list=False) -> int:
        """ type: asm / opcode / string """
        if not CurrentGadgets._initial_ropperbox(): 
            return 0
        find = find_str
        if find_type == "asm":
            find = asm(find).hex()
            func = getattr(CurrentGadgets.__internal_libcbox, "search_opcode")
        elif find_type == "opcode":
            func = getattr(CurrentGadgets.__internal_libcbox, "search_opcode")
        elif find_type == "string":
            func = getattr(CurrentGadgets.__internal_libcbox, "search_string")
        else:
            errlog_exit("Unsupported find_type, only: asm / opcode / string.")
        
        res = None
        if CurrentGadgets.__find_in_elf:
            try:
                res = func(find ,'elf', get_list)
                _base = 0
                if CurrentGadgets.__elf.pie:
                    _base = CurrentGadgets.__elf.address
                if get_list:
                    return [i + _base for i in res]
                else:
                    return _base + res
            except:
                pass

        if CurrentGadgets.__find_in_libc:
            res = func(find ,'libc', get_list)
            _base = 0
            if CurrentGadgets.__libc.pie:
                _base = CurrentGadgets.__libc.address
            if get_list:
                return [i + _base for i in res]
            else:
                return _base + res

        if not CurrentGadgets.__find_in_elf and not CurrentGadgets.__find_in_libc:
            errlog_exit("Have closed both elf finder and libc finder.")
        errlog_exit("Cannot find gadget: {}.".format(find_str))


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
    def pop_rdx_rbx_ret() -> int:
        """pop rdx; pop rbx; ret"""
        return CurrentGadgets._internal_find('get_pop_rdx_rbx_ret')

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
    def __try_get_rdx_gadget(rdx_val, rbx_val=0) -> list:
        try:
            addr = CurrentGadgets.pop_rdx_ret()
            return [addr, rdx_val]
        except:
            return [CurrentGadgets.pop_rdx_rbx_ret(), rdx_val, rbx_val]

    @staticmethod
    def execve_chain(bin_sh_addr=None) -> bytes:
        if not CurrentGadgets._initial_ropperbox():
            return None
        
        if CurrentGadgets.__arch == "i386":
            layout = [
                CurrentGadgets.pop_rbx_ret(),
                bin_sh_addr or CurrentGadgets.bin_sh(),
                CurrentGadgets.pop_rcx_ret(),
                0,
                CurrentGadgets.__try_get_rdx_gadget(0, bin_sh_addr or CurrentGadgets.bin_sh()),
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
                CurrentGadgets.__try_get_rdx_gadget(0),
                CurrentGadgets.pop_rax_ret(),
                0x3b,
                CurrentGadgets.syscall()
            ]
        else:
            errlog_exit("Unsupported arch: {}".format(CurrentGadgets.__arch))
        
        return flat(layout)

    @staticmethod
    def mprotect_chain(va, length=0x1000, prog=7) -> bytes:
        if not CurrentGadgets._initial_ropperbox():
            return None
        
        if CurrentGadgets.__arch == "i386":
            layout = [
                CurrentGadgets.pop_rbx_ret(),
                va,
                CurrentGadgets.pop_rcx_ret(),
                length,
                CurrentGadgets.__try_get_rdx_gadget(prog, va),
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
                CurrentGadgets.__try_get_rdx_gadget(prog),
                CurrentGadgets.pop_rax_ret(),
                10,
                CurrentGadgets.syscall()
            ]
        else:
            errlog_exit("Unsupported arch: {}".format(CurrentGadgets.__arch))
        
        return flat(layout)

    @staticmethod
    def orw_chain(flag_addr, buf_addr=None, flag_fd=3, write_fd=1, buf_len=0x30) -> bytes:
        if not CurrentGadgets._initial_ropperbox():
            return None
        
        if not buf_addr:
            buf_addr = flag_addr
        
        if CurrentGadgets.__arch == "i386":
            layout = [
                # open
                CurrentGadgets.pop_rbx_ret(),
                flag_addr,
                CurrentGadgets.pop_rcx_ret(),
                0,
                CurrentGadgets.pop_rax_ret(),
                5,
                CurrentGadgets.syscall_ret(),
                # read
                CurrentGadgets.pop_rbx_ret(),
                flag_fd,
                CurrentGadgets.pop_rcx_ret(),
                buf_addr,
                CurrentGadgets.__try_get_rdx_gadget(buf_len, flag_fd),
                CurrentGadgets.pop_rax_ret(),
                3,
                CurrentGadgets.syscall_ret(),
                # write
                CurrentGadgets.pop_rbx_ret(),
                write_fd,
                CurrentGadgets.pop_rax_ret(),
                4,
                CurrentGadgets.syscall_ret(),
            ]
        elif CurrentGadgets.__arch == "amd64":
            layout = [
                # open
                CurrentGadgets.pop_rdi_ret(),
                flag_addr,
                CurrentGadgets.pop_rsi_ret(),
                0,
                CurrentGadgets.pop_rax_ret(),
                2,
                CurrentGadgets.syscall_ret(),
                # read
                CurrentGadgets.pop_rdi_ret(),
                flag_fd,
                CurrentGadgets.pop_rsi_ret(),
                buf_addr,
                CurrentGadgets.__try_get_rdx_gadget(buf_len),
                CurrentGadgets.pop_rax_ret(),
                0x0,
                CurrentGadgets.syscall_ret(),
                # write
                CurrentGadgets.pop_rdi_ret(),
                write_fd,
                CurrentGadgets.pop_rax_ret(),
                0x1,
                CurrentGadgets.syscall_ret(),
            ]
        else:
            errlog_exit("Unsupported arch: {}".format(CurrentGadgets.__arch))
        
        return flat(layout)


    @staticmethod
    def write_by_magic(write_addr: int, ori: int, expected: int) -> bytes:
        if not CurrentGadgets._initial_ropperbox():
            return None
        if CurrentGadgets.__arch == "amd64":
            return flat([
                CurrentGadgets.find_gadget("pop rbx; pop rbp; pop r12; pop r13;"),
                expected - ori if expected > ori else expected - ori + 0x100000000,
                write_addr+0x3d, 0, 0, 0, 0,
                CurrentGadgets.magic_gadget()
            ])
            
        else:
            errlog_exit("Only used for amd64!")


def load_currentgadgets_background(find_in_elf=True, find_in_libc=True):
    Thread(target=CurrentGadgets.set_find_area, args=(find_in_elf, find_in_libc, True),daemon=True).start()