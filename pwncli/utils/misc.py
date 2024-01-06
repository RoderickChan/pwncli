"""
doctest for these functions
>>> int16('deadbeef')
3735928559

>>> int16('0xdeadbeef')
3735928559

>>> int8('7654')
4012

>>> int2('11010110110')
1718

>>> int16_ex('deadbeef')
3735928559

>>> int16_ex(b'deadbeef')
3735928559

>>> int16_ex(b'0xdeadbeef')
3735928559

>>> int8_ex(b'7654')
4012

>>> int2_ex(b'11010110110')
1718
"""



import functools
import os
import re
import struct
import subprocess
import sys
import time

import click
from pwn import ELF, context, flat, pack, unpack, which

__all__ = [
    # partial functions
    "int16",
    "int8",
    "int2",
    "int16_ex",
    "int8_ex",
    "int2_ex",
    "int_ex",
    "flat_z",
    # many log functions
    "log_ex",
    "log_ex_highlight",
    "log2_ex",
    "log2_ex_highlight",
    "warn_ex",
    "warn_ex_highlight",
    "errlog_ex",
    "errlog_ex_highlight",
    "errlog_exit",
    "errlog_ex_highlight_exit",
    "log_address",
    "leak",
    "log_address_ex",
    "leak_ex",
    "log_address_ex2",
    "leak_ex2",
    "log_libc_base_addr",
    "log_heap_base_addr",
    "log_code_base_addr",
    # get libc path by ldd command and get onegadget
    "ldd_get_libc_path",
    "one_gadget",
    "one_gadget_binary",
    
    # pack and unpack enhanced functions
    "hex_ex",
    "float2str_pure",
    
    "u8_ex",
    "u16_ex",
    "u24_ex",
    "u32_ex",
    "u64_ex",
    "p8_ex",
    "p16_ex",
    "p24_ex",
    "p32_ex",
    "p64_ex",
    "p32_float",
    "p64_float",
    "u32_float",
    "u64_float",
    "pad_ljust",
    "pad_rjust",
    "float_hexstr2int",
    "mem64_float2int",
    "mem32_float2int",
    "mem64_int2float",
    "mem32_int2float",
    
    # recv some address
    "recv_libc_addr",
    "recv_addr_startswith_0x",
    "get_segment_base_addr_by_proc_maps",
    
    # init with gift.io
    "init_x86_context",
    "init_x64_context",
    
    # tcachebins calcuator
    "calc_chunksize_corrosion",
    "calc_targetaddr_corrosion",
    "calc_idx_tcache",
    "calc_countaddr_tcache",
    "calc_entryaddr_tcache",
    "calc_countaddr_by_entryaddr_tcache",
    "calc_entryaddr_by_countaddr_tcache",
    
    # safe linking calculator
    "protect_ptr",
    "reveal_ptr",
    
    # some useful functions
    "step_split",
    "get_func_signature_str",
    "get_callframe_info",

]

int16_ex = int16 = functools.partial(int, base=16)
int8_ex = int8 = functools.partial(int, base=8)
int2_ex = int2 = functools.partial(int, base=2)
int_ex = int

flat_z = functools.partial(flat, filler=b"\x00")

def get_func_signature_str(func_name: str, *args, **kwargs):
    args_str = ""
    kwargs_str = ""
    if args:
        args_str = ", ".join(str(x) for x in args)
    if kwargs:
        if args_str:
            args_str += ", "
        kwargs_str = ", ".join("{}={}".format(_k, _v) for _k, _v in kwargs.items())
    return "{}({}{})".format(func_name, args_str, kwargs_str)



def step_split(s: str or bytes, step_len: int):
    """
    step_split("12345678", 4) -> "1234", "5678"
    step_split("1234567", 4) -> "1234", "567"
    """
    assert step_len > 0, "wrong step length!"
    start = 0
    end = start + step_len
    var = None
    while True:
        var = s[start:end]
        if len(var) != step_len:
            if len(var) != 0:
                yield var
            break
        yield var
        start = end
        end = start + step_len

        
def protect_ptr(address, next) -> int:
    return (address >> 12) ^ next

def reveal_ptr(addr) -> int:
    """
    addr = addr1 ^ addr2
    
    addr2 = addr1 + XXX
    
    calc the heap address
    """
    _res = addr
    for i in range(3):
        _res = (_res >> 12) ^ addr
    return _res


def get_callframe_info(depth:int=2):
    """Get stackframe info

    Args:
        depth (int, optional): The depth of stack frame. Defaults to 2

    Raises:
        OSError: If depth < 1, then raise OSError

    Returns:
        tuple: module_name, func_name, lineno
    """
    if depth < 1:
        raise OSError("depth must be bigger than 1")
    bf = sys._getframe()
    for i in range(depth - 1):
        bf = bf.f_back
    module_name = os.path.split(bf.f_code.co_filename)[1]
    func_name = bf.f_code.co_name
    lineno = bf.f_lineno
    return module_name, func_name, lineno


def log_ex(msg, *args):
    """Logs a message to stdout."""
    if args:
        msg %= args
    click.echo("[*] {}  {}".format(click.style("INFO", fg="green"), msg))


def log_ex_highlight(msg, *args):
    """Logs a message to stdout."""
    if args:
        msg %= args
    click.echo("[*] {}  {}".format(click.style("INFO", fg="green", bg="white"), msg))


def log2_ex(msg, *args):
    """Logs an important message to stdout."""
    if args:
        msg %= args
    click.echo("[#] {}  {}".format(click.style("IMPORTANT INFO", fg="blue"), msg))


def log2_ex_highlight(msg, *args):
    """Logs a message to stdout."""
    if args:
        msg %= args
    click.echo("[#] {}  {}".format(click.style("IMPORTANT INFO", fg="blue", bg="white"), msg))

def warn_ex(msg, *args):
    """Logs a warn message to stdout."""
    if args:
        msg %= args
    click.echo("[*] {}  {}".format(click.style("WARN", fg="yellow"), msg))


def warn_ex_highlight(msg, *args):
    """Logs a warn message to stdout."""
    if args:
        msg %= args
    click.echo("[*] {}  {}".format(click.style("WARN", fg="yellow", bg="white"), msg))


def errlog_ex(msg, *args):
    """Logs a message to stderr."""
    if args:
        msg %= args
    click.echo("[!] {}  {}".format(click.style("ERROR", fg="red"), msg))


def errlog_ex_highlight(msg, *args):
    """Logs a message to stdout."""
    if args:
        msg %= args
    click.echo("[!] {}  {}".format(click.style("ERROR", fg="red", bg="white"), msg))


def errlog_exit(msg, *args):
    """Logs a message to stderr and then exit."""
    errlog_ex(msg, *args)
    exit(-1)


def errlog_ex_highlight_exit(msg, *args):
    """Logs a message to stderr and then exit."""
    errlog_ex_highlight(msg, *args)
    exit(-1)


def log_address(desc:str, address:int):
    """Print address of hex fromat

    Args:
        desc (str): The description of address
        address (int): Address
    """
    log_ex("{} ===> {}".format(desc, hex(address)))

leak = log_address

def log_address_ex(variable_name:str, depth=2):
    """Log address from the variable's name by use of stack frame.

    Args:
        variable_name (str): The name.
        depth (int, optional): Stack frame depth. Default value is 2.
    """
    assert isinstance(variable_name, str), "variable_name must be a string!"
    assert depth >= 2, "depth error!"
    bf = sys._getframe()
    for i in range(depth - 1):
        bf = bf.f_back
    loc_var = bf.f_locals
    if variable_name not in loc_var:
        errlog_ex("Cannot find {}! Maybe the depth is wrong!".format(variable_name))
    else:
        var = loc_var[variable_name]
        assert isinstance(var, int), "The address is not int!"
        log_address(variable_name, var)

leak_ex = log_address_ex

def log_address_ex2(variable: int, depth: int=2):
    """Log address by variable

    Args:
        variable (int): The var you want to log, must be int.
        depth (int, optional): Stack frame depth. Defaults to 2.
    """
    assert isinstance(variable, int), "variable's type must be int!"
    assert depth >= 2, "depth error!"
    bf = sys._getframe()
    for i in range(depth - 1):
        bf = bf.f_back
    loc_var = bf.f_locals

    for k, v in loc_var.items():
        if isinstance(v, int) and v == variable:
            log_address(k, variable)
            return
    errlog_exit("Cannot find variable, check your depth!")

leak_ex2 = log_address_ex2

def log_libc_base_addr(address:int):
    log_address("libc_base_addr", address)


def log_heap_base_addr(address:int):
    log_address("heap_base_addr", address)


def log_code_base_addr(address:int):
    log_address("code_base_addr", address)


#-------------------------------libc-path and one_gadget-------------------

def ldd_get_libc_path(filepath:str) -> str:
    """Get binary file's libc.so.6 realpath.

    Args:
        filepath (str): The binary file path.

    Returns:
        str: Absolute path of libc used for the binary file.
    """
    rp = None
    try:
        out = subprocess.check_output(["ldd", filepath], encoding='utf-8').split()
        for o in out:
            if "/libc" in o:
                filedir = os.path.dirname(filepath)
                if o.startswith("/"):
                    rp = o
                else:
                    rp = os.path.realpath(os.path.join(filedir, o))
                break
    except:
        pass
    return rp


def one_gadget(condition:str, more=False, buildid=False):
    """Get all one_gadget by exec one_gadget.

    Args:
        condition (str): Libc.so path or buildid.
        more (bool, optional): Get more one_gadget or not. Defaults to False.

    Yields:
        int: Address of each one_gadget.
    """
    cmd_list = ["one_gadget", "--raw"]
    if re.match(r"[0-9a-f]+",condition, re.I):
        buildid = True
    else:
        buildid = False
    if buildid:
        cmd_list.extend(["--build-id"])
    elif not os.path.exists(condition):
        errlog_exit("Cannot exec one_gadget, file `{}' not exists!".format(condition))

    
    cmd_list.extend([condition])

    if more:
        cmd_list.append("-l")
        cmd_list.append("2")
    try:
        res = subprocess.check_output(cmd_list, encoding='utf-8').split()
        return [int(i) for i in res]
    except:
        errlog_exit("Cannot exec one_gadget, maybe you don't install one_gadget or filename is wrong or buildid is wrong! cmd: {}".format(" ".join(cmd_list)))


def one_gadget_binary(binary_path:str, more=False):
    """Get all one_gadget about an elf binary file.

    """
    binary_path = os.path.realpath(binary_path)
    rp = ldd_get_libc_path(binary_path)
    if rp:
        return one_gadget(rp, more)
    else:
        errlog_exit("Exec ldd {} fail!".format(binary_path))


#--------------------------------useful function------------------------------

def hex_ex(num: int) -> str:
    """hex_ex(0x0) -> 0x00
    
    hex_ex(0x111) -> 0x0111
    """
    s = hex(num)
    if len(s) % 2 == 0:
        return s
    return s[:2] + '0' + s[2:]

def float2str_pure(f: float):
    """float2str_pure(1.222e4) -> "12220.0"
    
    float2str_pure(1.222e-4) -> "0.0001222"
    """
    s = str(f)
    if 'e' in s:
        s2 = s.split('e')[1]
        s2 = int(s2)
        if s2 < 0:
            ff = "{" + ":.{}f".format(abs(s2-0x20)) + "}"
        else:
            ff = "{" + ":.{}f".format(0x20) + "}"
        return ff.format(f)        
    else:
        return s

def u8_ex(data: str or bytes) -> int:
    assert isinstance(data, (str, bytes)), "wrong data type!"
    length = len(data)
    assert length <= 1, "len(data) > 1!"
    if isinstance(data, str):
        data = data.encode('latin-1')
    data = data.ljust(1, b"\x00")
    return unpack(data, 8)

def u16_ex(data: str or bytes, **kwargs) -> int:
    assert isinstance(data, (str, bytes)), "wrong data type!"
    length = len(data)
    assert length <= 2, "len(data) > 2!"
    if isinstance(data, str):
        data = data.encode('latin-1')
    data = data.ljust(2, b"\x00")
    return unpack(data, 16, **kwargs)


def u24_ex(data: str or bytes, **kwargs) -> int:
    assert isinstance(data, (str, bytes)), "wrong data type!"
    length = len(data)
    assert length <= 3, "len(data) > 3!"
    if isinstance(data, str):
        data = data.encode('latin-1')
    data = data.ljust(3, b"\x00")
    return unpack(data, 24, **kwargs)


def u32_ex(data: str or bytes, **kwargs) -> int:
    assert isinstance(data, (str, bytes)), "wrong data type!"
    length = len(data)
    assert length <= 4, "len(data) > 4!"
    if isinstance(data, str):
        data = data.encode('latin-1')
    data = data.ljust(4, b"\x00")
    return unpack(data, 32, **kwargs)
    

def u64_ex(data: str or bytes, **kwargs) -> int:
    length = len(data)
    assert length <= 8, "len(data) > 8!"
    assert isinstance(data, (str, bytes)), "wrong data type!"
    if isinstance(data, str):
        data = data.encode('latin-1')
    data = data.ljust(8, b"\x00")
    return unpack(data, 64, **kwargs)


def p8_ex(num:int) -> bytes:
    if num < 0:
        num += 1 << 8
    num &= 0xff
    return pack(num, 8)


def p16_ex(num:int, **kwargs) -> bytes:
    if num < 0:
        num += 1 << 16
    num &= 0xffff
    return pack(num, 16, **kwargs)


def p24_ex(num: int, **kwargs) -> bytes:
    if num < 0:
        num += 1 << 24
    num &= 0xffffff
    return pack(num, 24, **kwargs)

def p32_ex(num:int, **kwargs) -> bytes:
    if num < 0:
        num += 1 << 32
    num &= 0xffffffff
    return pack(num, 32, **kwargs)


def p64_ex(num:int, **kwargs) -> bytes:
    if num < 0:
        num += 1 << 64
    num &= 0xffffffffffffffff
    return pack(num, 64, **kwargs)


def p32_float(num:float, endian="little") -> bytes:
    if endian.lower() == "little":
        return struct.pack("<f", num)
    elif endian.lower() == "big":
        return struct.pack(">f", num)
    else:
        raise RuntimeError("Wrong endian!")
        

def p64_float(num:float, endian="little") -> bytes:
    if endian.lower() == "little":
        return struct.pack("<d", num)
    elif endian.lower() == "big":
        return struct.pack(">d", num)
    else:
        raise RuntimeError("Wrong endian!")

def u32_float(data: bytes or str, endian="little") -> float:
    length = len(data)
    assert length <= 4, "len(data) > 4!"
    assert isinstance(data, (str, bytes)), "wrong data type!"
    if isinstance(data, str):
        data = data.encode('latin-1')
    if endian.lower() == "little":
        data = data.ljust(4, b"\x00")
        return struct.unpack("<f", data)[0]
    elif endian.lower() == "big":
        data = data.rjust(4, b"\x00")
        return struct.unpack(">f", data)[0]
    else:
        raise RuntimeError("Wrong endian!")
        

def u64_float(data: bytes or str, endian="little") -> float:
    length = len(data)
    assert length <= 8, "len(data) > 8!"
    assert isinstance(data, (str, bytes)), "wrong data type!"
    if isinstance(data, str):
        data = data.encode('latin-1')
    if endian.lower() == "little":
        data = data.ljust(8, b"\x00")
        return struct.unpack("<d", data)[0]
    elif endian.lower() == "big":
        data = data.rjust(8, b"\x00")
        return struct.unpack(">d", data)[0]
    else:
        raise RuntimeError("Wrong endian!")


def mem64_float2int(num:float, endian="little") -> int:
    """Get the int number of a double number when use the identical memeory. 
    
    For example, 0xdeadbeef's memory is 0x41ebd5b7dde00000, mem64_float2int(0xdeadbeef) to get 0x41ebd5b7dde00000"""
    return u64_ex(p64_float(num, endian))

def mem32_float2int(num:float, endian="little") -> int:
    """Get the int number of a float number when use the identical memeory. 
    
    For example, 0xdeadbeef's memory is 0x4f5eadbf, mem32_float2int(0xdeadbeef) to get 0x4f5eadbf"""
    return u32_ex(p32_float(num, endian))


def mem64_int2float(num: int, endian="little") -> float:
    """Get the double number of an int number when use the identical memeory. 
    
    For example, 0xdeadbeef's memory is 0x41ebd5b7dde00000, mem64_int2float(0x41ebd5b7dde00000) to get 0xdeadebeef"""
    res = u64_float(pack(num, endianness=endian, word_size=64))
    assert res != 0, "Invalid num!"
    return res

def mem32_int2float(num:float, endian="little") -> float:
    """Get the double number of an int number when use the identical memeory. 
    
    For example, 0xdeadbeef's memory is 0x4f5eadbf, mem32_int2float(0x4f5eadbf) to get 0xdeadbeef"""
    res = u32_float(pack(num, endianness=endian, word_size=32))
    assert res != 0, "Invalid num!"
    return res


def pad_ljust(payload: bytes or str, psz: int, filler: str="\x00") -> bytes:
    len_ = len(payload)
    comple = len_ % psz
    if comple > 0:
        return flat(payload, filler * (psz - comple))
    return payload

def pad_rjust(payload: bytes or str, psz: int, filler: str="\x00") -> bytes:
    len_ = len(payload)
    comple = len_ % psz
    if comple > 0:
        return flat(filler * (psz - comple), payload)
    return payload


def float_hexstr2int(data: str or bytes, hexstr=True, endian="little", bits=64) -> int:
    """float_hex2int('0x0.07f6d266e9fbp-1022') ---> 140106772946864
    
    Used for printf("%a")"""
    endian = endian.lower()
    assert endian in ("little", "big"), "only little or big for endian!"
    assert bits in (32, 64), "only 32 or 64 for bits!"
    
    if isinstance(data, bytes):
        data = data.decode()
    
    assert isinstance(data, str), "data is not str!"

    if endian == "little":
        ori = "<"
    else:
        ori = ">"
    
    if bits == 64:
        ch = "d"
    else:
        ch = "f"
    
    cmd = "from struct import pack\n"
    if hexstr:
        cmd += "a = float.fromhex('{}')\n"
    else:
        cmd += "a = float('{}')\n"
    
    cmd += "b = pack('{}{}', a)\n"
    cmd += "print(int.from_bytes(b, '{}'))"
    cmd = cmd.format(data, ori, ch, endian)
    try:
        res = subprocess.check_output([sys.executable, "-c", cmd]).strip()
        return int(res)
    except:
        errlog_exit("float_hex2int failed, check cmd: \n{}".format(cmd))
        

def recv_libc_addr(io, *, bits=64, offset=0, timeout=5) -> int:
    """Calcuate libc-base addr while recv '\x7f' in amd64 or '\xf7' in i386.

    Args:
        p (tube): Tube.
        bits (int, optional): 32 or 64. Defaults to 64.
        offset (int, optional): Help to get libc-base address. Defaults to 0.

    Raises:
        RuntimeError: Raise error if cannot recv bytes about libc-addr in 3 seconds.

    Returns:
        int: Libc address
    """
    assert bits == 32 or bits == 64
    contains = b"\x7f" if bits == 64 else b"\xf7"
    m = io.recvuntil(contains, timeout=timeout)
    if contains not in m:
        raise RuntimeError("Cannot get libc addr")
    if bits == 32:
        return u32_ex(m[-4:]) - offset
    else:
        return u64_ex(m[-6:]) - offset

def recv_addr_startswith_0x(io, *, prefix="", suffix="", has_0x=True, timeout=5) -> int:
    """Receive data with addressa which starts with 0x or 0X.

    Args:
        io (tube): Tube.

    Raises:
        RuntimeError: Raise error if cannot recv addr.

    Returns:
        int: Some address
    """
    if len(suffix) == 0:
        suffix = "[^0-9A-Fa-f]"
    if has_0x:
        mid = "(0[xX][0-9A-Fa-f]+)"
    else:
        mid = "([0-9A-Fa-f]+)"
    m = io.recvregex(prefix + mid + suffix, capture=True,timeout=timeout)
    if not m:
        raise RuntimeError("Cannot get 0x???? addr")
    m = m.group(1)
    if has_0x and (b"0x" not in m) and (b"0x" not in m):
        raise RuntimeError("Cannot get 0x???? addr")
    return int16_ex(m)





def get_segment_base_addr_by_proc_maps(pid:int, filename:str=None) -> dict:
    """Read /proc/pid/maps file to get base address. Return a dictionary obtaining keys: 'code',
    'libc', 'ld', 'stack', 'heap', 'vdso'.

    Args:
        pid (int): Pid of process.
        filename (str, optional): Filename to get code base address. Default is None.

    Returns:
        dict: All segment address. Key: str, Val: int.
    """
    assert isinstance(pid, int), "error type!"
    res = None
    try:
        res = subprocess.check_output(["cat", "/proc/{}/maps".format(pid)]).decode()
        if "/libc" not in res or "/ld" not in res: # again
            # wait for ld load libc
            time.sleep(1)
            try:
                res = subprocess.check_output(["cat", "/proc/{}/maps".format(pid)]).decode()
            except:
                errlog_exit("cat /proc/{}/maps faild!".format(pid))

    except:
        errlog_exit("cat /proc/{}/maps faild!".format(pid))
    _d = {}
    if not res:
        warn_ex("'cat /proc/{}/maps' gets empty result, are you sure the process is alive?".format(pid))
        return _d
    res = res.split("\n")
    code_flag = 0
    libc_flag = 0
    ld_flag = 0

    for r in res:
        rc = re.compile(r"^([0-9a-f]{6,14})-([0-9a-f]{6,14})", re.S)
        rc = rc.findall(r)
        if len(rc) != 1 or len(rc[0]) != 2:
            continue
        start_addr = int(rc[0][0], base=16)
        end_addr = int(rc[0][1], base=16)
        if (filename is not None) and (not code_flag) and r.endswith(filename):
            code_flag = 1
            _d['code'] = start_addr
        elif (not libc_flag) and ("/libc" in r):
            libc_flag = 1
            _d['libc'] = start_addr
        elif (not ld_flag) and ("/ld" in r):
            ld_flag = 1
            _d['ld'] = start_addr
        elif "heap" in r:
            _d['heap'] = start_addr
        elif "stack" in r:
            _d['stack'] = start_addr  
        elif "vdso" in r:
            _d['vdso'] = start_addr
    return _d

#--------------------helper of pwncli script mode---------------------
def _assign_globals(_io, _g):
    _g['s'] = _io.send
    _g['sl'] = _io.sendline
    _g['sla'] = _io.sendlineafter
    _g['sa'] = _io.sendafter
    _g['slt'] = _io.sendlinethen
    _g['st'] = _io.sendthen
    _g['r'] = _io.recv
    _g['rn'] = _io.recvn
    _g['rr'] = _io.recvregex
    _g['ru'] = _io.recvuntil
    _g['ra'] = _io.recvall
    _g['rl'] = _io.recvline
    _g['rs'] = _io.recvlines
    _g['rls'] = _io.recvline_startswith
    _g['rle'] = _io.recvline_endswith
    _g['rlc'] = _io.recvline_contains
    _g['ia'] = _io.interactive
    _g['ic'] = _io.close
    _g['cr'] = _io.can_recv

def init_x86_context(io, globals: dict, log_level: str="debug", timeout: int=5, arch: str="i386", os: str="linux", endian: str="little"):
    """ Usage: 
    
    from pwncli import * 
    
    p = process(xxx)
    
    init_x86_context(p, globals())
    """
    context.update(arch=arch, os=os, endian=endian, log_level=log_level, timeout=timeout)
    _assign_globals(io, globals)

def init_x64_context(io, globals: dict, log_level: str="debug", timeout: int=5, arch: str="amd64", os: str="linux", endian: str="little"):
    """ Usage: 
    
    from pwncli import * 
    
    p = process(xxx)
    
    init_x64_context(p, globals())
    """
    context.update(arch=arch, os=os, endian=endian, log_level=log_level, timeout=timeout)
    _assign_globals(io, globals)


#-------------------------------calc related--------------------------

def calc_chunksize_corrosion(targetaddr: int, main_arena_fastbinsY_addr: int, bits: int=64) -> int:
    """house of corrosion

    Calculate chunksize by target address
    """
    assert bits == 64 or bits == 32, "wrong bits!"
    assert targetaddr >= main_arena_fastbinsY_addr, "wrong addr!"
    assert targetaddr & ((bits >> 3) - 1) == 0, "target address not pad!"
    return (targetaddr - main_arena_fastbinsY_addr) * 2 + (bits >> 1)


def calc_targetaddr_corrosion(chunksize: int, main_arena_fastbinsY_addr: int, bits: int=64) -> int:
    """house of corrosion

    Calculate target address by chunksize
    """
    assert bits == 64 or bits == 32, "wrong bits!"
    pad = bits >> 1
    assert chunksize & ((pad >> 1) - 1) == 0, "chunksize not pad!"
    assert chunksize >= pad, "wrong chunksize!"
    return ((chunksize - pad) >> 1) + main_arena_fastbinsY_addr


def calc_idx_tcache(chunksize: int, bits: int=64):
    """Calculate index in tcache by chunksize"""
    assert bits == 64 or bits == 32, "wrong bits!"
    pad = bits >> 1
    assert chunksize & ((pad >> 1) - 1) == 0, "chunksize not pad!"
    assert chunksize >= pad, "invalid chunksize!"
    return (chunksize - pad) // (pad >> 1)


def calc_countaddr_tcache(chunksize: int, tcache_perthread_addr: int, sizeofcount: int=2, bits: int=64):
    """tcache_perthread_addr: 0x555555555010
    
    Calculate &tcache->counts[idx] 
    """
    assert sizeofcount == 1 or sizeofcount == 2, "glibc version >= 2.31, sizeof(count) = 2, otherwise 1"
    idx = calc_idx_tcache(chunksize, bits)
    return idx * sizeofcount + tcache_perthread_addr


def calc_entryaddr_tcache(chunksize: int, tcache_perthread_addr: int, sizeofcount: int=2, bits: int=64):
    """tcache_perthread_addr: 0x555555555010
    
    Calculate &tcache->entries[idx] 
    """
    assert sizeofcount == 1 or sizeofcount == 2, "glibc version >= 2.31, sizeof(count) = 2, otherwise 1"
    idx = calc_idx_tcache(chunksize, bits)
    start_addr = tcache_perthread_addr + sizeofcount * 64
    return idx * (bits >> 3) + start_addr


def calc_countaddr_by_entryaddr_tcache(tcache_perthread_addr: int, entryaddr: int, sizeofcount: int=2, bits: int=64):
    """tcache_perthread_addr: 0x555555555010
    
    Calculate &tcache->counts[idx] by &tcache->entries[idx]
    """
    assert sizeofcount == 1 or sizeofcount == 2, "glibc version >= 2.31, sizeof(count) = 2, otherwise 1"
    start_addr = tcache_perthread_addr + sizeofcount * 64
    assert entryaddr >= start_addr, "invalid address!"
    dis = entryaddr - start_addr
    assert dis & ((bits >> 3) - 1) == 0, "distance not pad!"
    idx = dis // (bits >> 3)
    return idx * sizeofcount + tcache_perthread_addr


def calc_entryaddr_by_countaddr_tcache(tcache_perthread_addr: int, countaddr: int, sizeofcount: int=2, bits: int=64):
    """tcache_perthread_addr: 0x555555555010
    
    Calculate &tcache->entries[idx] by &tcache->counts[idx]
    """
    assert sizeofcount == 1 or sizeofcount == 2, "glibc version >= 2.31, sizeof(count) = 2, otherwise 1"
    assert countaddr >= tcache_perthread_addr, "invalid address!"
    dis = countaddr - tcache_perthread_addr
    assert dis & (sizeofcount - 1) == 0, "distance not pad!"
    idx = dis // sizeofcount
    start_addr = tcache_perthread_addr + sizeofcount * 64
    return idx * (bits >> 3) + start_addr


#-------------------------------private-------------------------------
def _get_elf_arch_info(filename):
    _e = ELF(filename, checksec=False)
    arch = _e.arch
    del _e
    return arch

def _in_tmux():
    return bool('TMUX' in os.environ and which('tmux'))

def _in_wsl():
    if os.path.exists('/proc/sys/kernel/osrelease'):
        with open('/proc/sys/kernel/osrelease', 'rb') as f:
            is_in_wsl = b'icrosoft' in f.read()
        if is_in_wsl and which('wsl.exe') and which("cmd.exe"):
            return True
    return False

def _get_gdb_plugin_info():
    with open(os.path.expanduser("~/.gdbinit"), "a+", encoding="utf-8") as f:
        f.seek(0, 0)
        for line in f:
            if line.strip().startswith("source"):
                if "pwndbg" in line:
                    return "pwndbg"
                elif "gef" in line:
                    return "gef"
                elif "peda" in line:
                    return "peda"
    return None

if __name__ == "__main__":
    import doctest
    doctest.testmod(verbose=True)
