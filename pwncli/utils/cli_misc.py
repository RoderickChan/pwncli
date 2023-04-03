#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : cli_misc.py
@Time    : 2022/12/12 21:34:37
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : None
'''


import functools
import os
import subprocess
import time
from threading import Lock, Thread

from pwn import (ELF, asm, atexit, attach, context, flat, process, remote,
                 sleep, wget, which)

from pwncli.cli import gift

from .decorates import deprecated, unused
from .gadgetbox import ElfGadgetBox, RopgadgetBox, RopperArchType, RopperBox
from .misc import (_in_tmux, _in_wsl, errlog_exit, get_callframe_info,
                   get_flag_when_get_shell, get_segment_base_addr_by_proc_maps,
                   ldd_get_libc_path, log2_ex, log_code_base_addr, log_ex,
                   log_libc_base_addr, one_gadget, one_gadget_binary,
                   recv_libc_addr, warn_ex)
from .syscall_num import SyscallNumber

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
    "send_continue2current_gdbprocess",
    "add_struct2current_gdb_by_member",
    "add_struct2current_gdb_by_file",
    "add_show_struct_command2current_gdb",
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
    "CurrentGadgets", "load_currentgadgets_background", "CG",
    "kill_heaptrace", "launch_heaptrace", "launch_gdb",
    "only_debug", "only_gdb", "only_remote", "only_nogdb"
    ]

#-------------------------------------------------------------------------------------

# only call when debug command is used
def only_debug(show_warn=True):
    def wrapper1(func_call):
        @functools.wraps(func_call)
        def wrapper2(*args, **kwargs):
            if gift.debug and not gift.remote and gift.io:
                res = func_call(*args, **kwargs)
            else:
                if show_warn:
                    warn_ex(
                        "'{}' will not be called because debug mode is not enabled.".format(func_call.__name__))
                res = None
            return res
        return wrapper2
    return wrapper1


# only call when debug command is used and gdb is used
def only_gdb(show_warn=True):
    def wrapper1(func_call):
        @functools.wraps(func_call)
        def wrapper2(*args, **kwargs):
            if gift.debug and not gift.remote and gift.io and gift.gdb_obj:
                res = func_call(*args, **kwargs)
            else:
                if show_warn:
                    warn_ex(
                        "'{}' will not be called because debug mode and gdb are not enabled.".format(func_call.__name__))
                res = None
            return res
        return wrapper2
    return wrapper1

# only call when debug command is used and gdb is not used
def only_nogdb(show_warn=True):
    def wrapper1(func_call):
        @functools.wraps(func_call)
        def wrapper2(*args, **kwargs):
            if gift.debug and not gift.remote and gift.io and not gift.gdb_obj and not gift.gdb_pid:
                res = func_call(*args, **kwargs)
            else:
                if show_warn:
                    warn_ex(
                        "'{}' will not be called because gdb is enabled.".format(func_call.__name__))
                res = None
            return res
        return wrapper2
    return wrapper1

# only call when gift.remote is True
def only_remote(show_warn=True):
    def wrapper1(func_call):
        @functools.wraps(func_call)
        def wrapper2(*args, **kwargs):
            if gift.remote and not gift.debug and gift.io:
                res = func_call(*args, **kwargs)
            else:
                if show_warn:
                    warn_ex(
                        "'{}' will not be called because remote mode is not enabled.".format(func_call.__name__))
                res = None
            return res
        return wrapper2
    return wrapper1

#-------------------------------------------------------------------------------------

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
    input("👉 Press any key to continue......")

S = stop

_tmux_pane = None
_gnome_pid = -1
_heaptrace_pid = -100

def _kill_heaptrace_in_tmux_pane():
    global _tmux_pane, _heaptrace_pid
    os.system("tmux send-keys -t {} C-c 2>/dev/null".format(_tmux_pane))
    os.system("tmux kill-pane -t {} 2>/dev/null".format(_tmux_pane))

def _kill_heaptrace_in_gnome():
    # global _gnome_pid, _heaptrace_pid
    # os.system("kill -SIGINT {} 2>/dev/null".format(_heaptrace_pid))
    # os.system("kill -9 {} 2>/dev/null".format(_gnome_pid))
    pass

def _kill_heaptrace_in_wsl():
    # global _heaptrace_pid
    # os.system("kill -SIGINT {} 2>/dev/null".format(_heaptrace_pid))
    pass

def _launch_heaptrace_in_tmux():
    global _tmux_pane, _heaptrace_pid
    pid = gift.io.pid
    _tmux_pane= subprocess.check_output(["tmux", "splitw", "-h", '-F#{session_name}:#{window_index}.#{pane_index}', "-P"]).decode().strip()
    atexit.register(_kill_heaptrace_in_tmux_pane)
    os.system("tmux send-keys -t {} 'heaptrace --attach {}' C-m".format(_tmux_pane, pid))
    os.system("tmux select-pane -L")


def _launch_heaptrace_in_wsl():
    global _heaptrace_pid
    pid = gift.io.pid
    cmd = "cmd.exe /c start wt.exe wsl.exe -d {} bash -c \"{}\"".format(os.getenv("WSL_DISTRO_NAME"), "heaptrace --attach {}".format(pid))
    os.system(cmd)


def _launch_heaptrace_in_gnome():
    global _gnome_pid, _heaptrace_pid
    pid = gift.io.pid
    p = subprocess.Popen(["gnome-terminal", "--", "sh", "-c", "heaptrace --attach {}".format(pid)])
    global _gnome_pid
    _gnome_pid = p.pid
    atexit.register(_kill_heaptrace_in_gnome)

@only_nogdb()
def kill_heaptrace():
    if _in_tmux():
        _kill_heaptrace_in_tmux_pane()  
    elif _in_wsl():
        _kill_heaptrace_in_wsl()
    elif which("gnome-terminal"):
        _kill_heaptrace_in_gnome()

@only_nogdb()
def launch_heaptrace(stop_=True):
    if not which("heaptrace"):
        res = input("Install heaptrace from https://github.com/Arinerron/heaptrace/releases/download/2.2.8/heaptrace? [y/n]").strip()
        if res != "y":
            errlog_exit("Cannot find heaptrace!")
        try:
            wget("https://github.com/Arinerron/heaptrace/releases/download/2.2.8/heaptrace", save=True, timeout=300)
            subprocess.check_output(["chmod", "+x", "heaptrace"])
            bin_path = "$HOME/.local/bin" if os.getuid() != 0 else "/usr/local/bin"
            subprocess.check_output(["mv", "heaptrace", bin_path])
        except:
            errlog_exit("Cannot download or install heaptrace!")
    
    if _in_tmux():
        _launch_heaptrace_in_tmux()
    elif _in_wsl() and which("wt.exe"):
        _launch_heaptrace_in_wsl()
        sleep(1)
    elif which("gnome-terminal"):
        _launch_heaptrace_in_gnome()
    else:
        errlog_exit("Don't know how to launch heaptrace!")
    stop(stop_)

@only_nogdb()
def launch_gdb(script: str, stop_=True):
    attach(gift.io, gdbscript=script)
    stop(stop_)

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
@only_debug()
def __get_current_segment_base_addr(use_cache=True) -> dict:
    global _cache_segment_base_addr
    """Get current process's segments' base address."""
    if use_cache and _cache_segment_base_addr is not None:
        return _cache_segment_base_addr

    pid = gift.io.proc.pid
    filename = gift.filename
    if filename is not None:
        filename = os.path.split(os.path.abspath(filename))[1]
    _cache_segment_base_addr = get_segment_base_addr_by_proc_maps(pid, filename)
    return _cache_segment_base_addr


@only_debug()
def get_current_codebase_addr(use_cache=True) -> int:
    r = __get_current_segment_base_addr(use_cache)
    return r['code']

@only_debug()
def get_current_libcbase_addr(use_cache=True) -> int:
    r = __get_current_segment_base_addr(use_cache)
    return r['libc']

@only_debug()
def get_current_stackbase_addr(use_cache=True) -> int:
    r = __get_current_segment_base_addr(use_cache)
    return r['stack']

@only_debug()
def get_current_heapbase_addr(use_cache=True) -> int:
    r = __get_current_segment_base_addr(use_cache)
    return r['heap']


#----------------------------gdb related-------------------------
from pwncli.utils.gdb_helper import *


@only_gdb()
def kill_current_gdb():
    """Kill current gdb process."""
    try:
        kill_gdb(gift['gdb_obj'])
    except:
        kill_gdb(gift['gdb_pid'])

@only_gdb()
def send_signal2current_gdbprocess(sig_val:int=2):
    os.system("kill -{} {}".format(sig_val, gift['gdb_pid']))
    time.sleep(0.2)

@only_gdb()
def send_continue2current_gdbprocess():
    execute_cmd_in_gdb(gift["gdb_obj"], "continue")
    

@only_gdb()
def execute_cmd_in_current_gdb(cmd:str):
    """Execute commands in current gdb, split commands by ';' or \\n."""
    execute_cmd_in_gdb(gift["gdb_obj"], cmd)
    
@only_gdb()
def set_current_pie_breakpoints(offset:int):
    """Set breakpoints by offset when binary's PIE enabled. Only support for `pwndbg'."""
    set_pie_breakpoints(gift["gdb_obj"], offset)

@only_gdb()
def tele_current_pie_content(offset:int, number=10):
    """Telescope current content by offset when binary's PIE enabled. Only support for 'pwndbg'."""
    tele_pie_content(gift["gdb_obj"], offset, number)

@only_gdb()
def add_struct2current_gdb_by_member(struct_name, add_show_cmd=False, *struct_mems, **struct_memskw):
    add_struct_by_member(gift["gdb_obj"], struct_name, add_show_cmd, *struct_mems, **struct_memskw)

@only_gdb()
def add_struct2current_gdb_by_file(file_content, add_show_cmd=False, *struct_names):
    add_struct_by_file(gift["gdb_obj"], file_content, add_show_cmd, *struct_names)

@only_gdb()
def add_show_struct_command2current_gdb(*struct_names):
    add_show_struct_command(gift["gdb_obj"], *struct_names)

#-----------------other------------------------

def recv_current_libc_addr(offset:int=0, timeout=5):
    if not gift.get("elf", None):
        errlog_exit("Can not get current libc addr because of no elf.")
    if not gift.get('io', None):
        errlog_exit("Can not get current libc addr because of no io.")
    
    return recv_libc_addr(gift['io'], bits=gift['elf'].bits, offset=offset, timeout=timeout)


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
    """Only used for debug/remote command"""
    io = None
    if gift.get('debug'):
        io = context.binary.process(gift.process_argv, timeout=gift.context_timeout, env=gift.process_env)
    elif gift.get('remote'):
        io = remote(gift.ip, gift.port, timeout=gift.context_timeout)
    else:
        raise RuntimeError("copy_current_io error, no debug and no remote!")
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

def rl(*args, **kwargs) -> bytes:
    """recvline"""
    io = gift.get("io", None)
    if io:
        return io.recvline(*args, **kwargs)

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

def cr(timeout=0) -> bool:
    """can_recv"""
    io = gift.get("io", None)
    if io:
        return io.can_recv(timeout)

# ----------------------------------gadget----------------

class CurrentGadgets:
    __internal_gadgetbox = None
    __elf = None
    __libc = None
    __arch = None
    __find_in_elf = None
    __find_in_libc = None
    __loaded = False

    _mutex = Lock()

    @staticmethod
    def set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False):
        CurrentGadgets.__find_in_elf = find_in_elf
        CurrentGadgets.__find_in_libc = find_in_libc
        if do_initial:
            CurrentGadgets._initial_gadgetbox()

    @staticmethod
    def set_debug(debug):
        CurrentGadgets._initial_gadgetbox()
        CurrentGadgets.__internal_gadgetbox.set_debug(debug)

    @staticmethod
    def _initial_gadgetbox() -> bool:
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

        try:
            CurrentGadgets.__internal_gadgetbox = RopgadgetBox()
        except:
            try:
                CurrentGadgets.__internal_gadgetbox = RopperBox()
            except:
                CurrentGadgets.__internal_gadgetbox = ElfGadgetBox()

        res = False
        if elf:
            if elf.arch not in __arch_mapping:
                log2_ex("Unsupported arch, only for i386 and amd64.")
            else:
                CurrentGadgets.__arch = elf.arch

                if CurrentGadgets.__internal_gadgetbox.box_name == "ropper":
                    CurrentGadgets.__internal_gadgetbox.add_file("elf", elf.path, __arch_mapping[elf.arch])
                else:
                    CurrentGadgets.__internal_gadgetbox.add_file("elf", elf.path, elf.arch)

                if CurrentGadgets.__elf.pie:
                    CurrentGadgets.__internal_gadgetbox.set_imagebase("elf", CurrentGadgets.__elf.address)
                res = True
        if libc:
            if libc.arch not in __arch_mapping:
                log2_ex("Unsupported arch, only for i386 and amd64..")
            else:
                CurrentGadgets.__arch = libc.arch
                if CurrentGadgets.__internal_gadgetbox.box_name == "ropper":
                    CurrentGadgets.__internal_gadgetbox.add_file("libc", libc.path, __arch_mapping[elf.arch])
                else:
                    CurrentGadgets.__internal_gadgetbox.add_file("libc", libc.path, libc.arch)

                if CurrentGadgets.__libc.pie:
                    CurrentGadgets.__internal_gadgetbox.set_imagebase("libc", CurrentGadgets.__libc.address)
                res = True
        
        CurrentGadgets.__loaded = res
        CurrentGadgets._mutex.release()
        return res

    @staticmethod
    def reset():
        CurrentGadgets.__internal_gadgetbox = None
        CurrentGadgets.__elf = None
        CurrentGadgets.__libc = None
        CurrentGadgets.__arch = None
        CurrentGadgets.__find_in_elf = None
        CurrentGadgets.__find_in_libc = None
        CurrentGadgets.__loaded = False
        CurrentGadgets._initial_gadgetbox()

    @staticmethod
    def _internal_find(func_name):
        if not CurrentGadgets._initial_gadgetbox(): 
            return 0
        func = getattr(CurrentGadgets.__internal_gadgetbox, func_name)
        if CurrentGadgets.__find_in_elf or (CurrentGadgets.__find_in_elf is None and (CurrentGadgets.__elf.address or CurrentGadgets.__elf.statically_linked)):
            if CurrentGadgets.__elf.pie:
                CurrentGadgets.__internal_gadgetbox.set_imagebase("elf", CurrentGadgets.__elf.address)
            try:
                res = func('elf')
                return res
            except:
                pass
        
        if CurrentGadgets.__find_in_libc or (CurrentGadgets.__find_in_libc is None and CurrentGadgets.__libc.address):
            if CurrentGadgets.__libc.pie:
                CurrentGadgets.__internal_gadgetbox.set_imagebase("libc", CurrentGadgets.__libc.address)
            res = func('libc')
            return res
        
        if not CurrentGadgets.__find_in_elf and not CurrentGadgets.__find_in_libc:
            log2_ex("Have closed both elf finder and libc finder, please call CurrentGadgets.set_find_area to set a finder.")
        errlog_exit("Cannot find gadget using '{}'.".format(func_name))


    @staticmethod
    @functools.lru_cache(maxsize=128, typed=True)
    def find_gadget(find_str : str, find_type='asm', get_list=False) -> int:
        """ type: asm / opcode / string """
        if not CurrentGadgets._initial_gadgetbox(): 
            return 0
        find = find_str
        if find_type == "asm":
            find = asm(find).hex()
            func = getattr(CurrentGadgets.__internal_gadgetbox, "search_opcode")
        elif find_type == "opcode":
            func = getattr(CurrentGadgets.__internal_gadgetbox, "search_opcode")
        elif find_type == "string":
            func = getattr(CurrentGadgets.__internal_gadgetbox, "search_string")
        else:
            errlog_exit("Unsupported find_type, only: asm / opcode / string.")
        
        res = None
        if CurrentGadgets.__find_in_elf:
            if CurrentGadgets.__elf.pie:
                CurrentGadgets.__internal_gadgetbox.set_imagebase("elf", CurrentGadgets.__elf.address)
            try:
                return func(find ,'elf', get_list)
            except:
                pass

        if CurrentGadgets.__find_in_libc:
            if CurrentGadgets.__libc.pie:
                CurrentGadgets.__internal_gadgetbox.set_imagebase("libc", CurrentGadgets.__libc.address)
            return func(find ,'libc', get_list)

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
    def __inner_chain(i386_num, syscall_num, para1, para2=None, para3=None) -> bytes:
        if not CurrentGadgets._initial_gadgetbox():
            return None
        if CurrentGadgets.__arch == "i386":
            if para1 < 0:
                para1 += 1 << 32
            layout = [
                CurrentGadgets.pop_rbx_ret(),
                para1
                ]
            if para2 is not None:
                layout.append(CurrentGadgets.pop_rcx_ret())
                layout.append(para2)

            if para3 is not None:
                layout.append(CurrentGadgets.__try_get_rdx_gadget(para3, para1))
            
            layout.append(CurrentGadgets.pop_rax_ret())
            layout.append(i386_num)
            layout.append(CurrentGadgets.syscall_ret())
            return flat(layout)

        elif CurrentGadgets.__arch == "amd64":
            if para1 < 0:
                para1 += 1 << 64
            layout = [
                CurrentGadgets.pop_rdi_ret(),
                para1
                ]
            if para2 is not None:
                layout.append(CurrentGadgets.pop_rsi_ret())
                layout.append(para2)
            
            if para3 is not None:
                layout.append(CurrentGadgets.__try_get_rdx_gadget(para3))
            
            layout.append(CurrentGadgets.pop_rax_ret())
            layout.append(syscall_num)
            layout.append(CurrentGadgets.syscall_ret())
            return flat(layout)
        else:
            errlog_exit("Unsupported arch: {}".format(CurrentGadgets.__arch))
        

    @staticmethod
    def syscall_chain(syscall_num, para1, para2=None, para3=None) -> bytes:
        return CurrentGadgets.__inner_chain(syscall_num, syscall_num, para1, para2, para3)

    @staticmethod
    def execve_chain(bin_sh_addr=None) -> bytes:
        return CurrentGadgets.__inner_chain(SyscallNumber.i386.EXECVE, SyscallNumber.amd64.EXECVE, bin_sh_addr or CurrentGadgets.bin_sh(), 0, 0)

    @staticmethod
    def mprotect_chain(va, length=0x1000, prog=7) -> bytes:
        return CurrentGadgets.__inner_chain(SyscallNumber.i386.MPROTECT, SyscallNumber.amd64.MPROTECT, va, length, prog)

    @staticmethod
    def open_chain(fileaddr, flag=0, mode=None) -> bytes:
        return CurrentGadgets.__inner_chain(SyscallNumber.i386.OPEN, SyscallNumber.amd64.OPEN, fileaddr, flag, mode)

    @staticmethod
    def openat_chain(fileaddr, flag=0) -> bytes:
        return CurrentGadgets.__inner_chain(SyscallNumber.i386.OPENAT, SyscallNumber.amd64.OPENAT, -100, fileaddr, flag)

    @staticmethod
    def read_chain(fd, buf, length) -> bytes:
        return CurrentGadgets.__inner_chain(SyscallNumber.i386.READ, SyscallNumber.amd64.READ, fd, buf, length)

    @staticmethod
    def write_chain(fd, buf, length) -> bytes:
        return CurrentGadgets.__inner_chain(SyscallNumber.i386.WRITE, SyscallNumber.amd64.WRITE, fd, buf, length)


    @staticmethod
    def orw_chain(flag_addr, buf_addr=None, flag_fd=3, write_fd=1, buf_len=0x30) -> bytes:
        return CurrentGadgets.open_chain(flag_addr) + \
            CurrentGadgets.read_chain(flag_fd, buf_addr or flag_addr, buf_len) + \
            CurrentGadgets.write_chain(write_fd, buf_addr or flag_addr, buf_len)

    @staticmethod
    def otrw_chain(flag_addr, buf_addr=None, flag_fd=3, write_fd=1, buf_len=0x30) -> bytes:
        return CurrentGadgets.openat_chain(flag_addr) + \
            CurrentGadgets.read_chain(flag_fd, buf_addr or flag_addr, buf_len) + \
            CurrentGadgets.write_chain(write_fd, buf_addr or flag_addr, buf_len)

    @staticmethod
    def write_by_magic(write_addr: int, ori: int, expected: int) -> bytes:
        if not CurrentGadgets._initial_gadgetbox():
            return None
        if CurrentGadgets.__arch == "amd64":
            return flat([
                CurrentGadgets.find_gadget("5b5d415c415d415e415fc3", 'opcode'),
                expected - ori if expected > ori else expected - ori + 0x100000000,
                write_addr+0x3d, 0, 0, 0, 0,
                CurrentGadgets.magic_gadget()
            ])
            
        else:
            errlog_exit("Only used for amd64!")


def load_currentgadgets_background(find_in_elf=True, find_in_libc=True):
    Thread(target=CurrentGadgets.set_find_area, args=(find_in_elf, find_in_libc, True),daemon=True).start()
    

CG = CurrentGadgets