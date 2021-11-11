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



import sys
import os
import re
import functools
import subprocess
import struct
from pwn import unpack, pack


int16 = functools.partial(int, base=16)
int8 = functools.partial(int, base=8)
int2 = functools.partial(int, base=2)

int16_ex = lambda x: int16(x.decode()) if isinstance(x, bytes) else int16(x)
int8_ex = lambda x: int8(x.decode()) if isinstance(x, bytes) else int8(x)
int2_ex = lambda x: int2(x.decode()) if isinstance(x, bytes) else int2(x)

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


# print str with color
class FontColor:
    BLACK = 30
    RED = 31
    GREEN = 32
    YELLOW = 33
    BLUE = 34
    AMARANTH = 35
    CYAN = 36
    WHITE = 37


class BackgroundColor:
    NOCOLOR = -1
    BLACK = 40
    RED = 41
    GREEN = 42
    YELLOW = 43
    BLUE = 44
    AMARANTH = 45
    CYAN = 46
    WHITE = 47


class TerminalMode:
    DEFAULT = 0
    HIGHLIGHT = 1
    UNDERLINE = 4
    TWINKLE = 5
    ANTI_WHITE = 7
    INVISIBLE = 8


def __check(font_color: int, background_color: int, terminal_mode: int) -> bool:
    b1 = (font_color >= FontColor.BLACK and font_color <= FontColor.WHITE)
    b2 = (background_color >= BackgroundColor.BLACK and background_color <= BackgroundColor.WHITE) or background_color == BackgroundColor.NOCOLOR
    b3 = (terminal_mode >= TerminalMode.DEFAULT and terminal_mode <= TerminalMode.INVISIBLE and terminal_mode != 2 and terminal_mode != 3 and terminal_mode != 6)
    return (b1 and b2 and b3)


def get_str_with_color(print_str: str, *,
                       font_color: int = FontColor.WHITE,
                       background_color: int = BackgroundColor.NOCOLOR,
                       terminal_mode: int = TerminalMode.DEFAULT) -> str:
    """
    Decorate a string with color

    Args:
        print_str (str): The str you want to modify.
        font_color (int, optional): Font color. Defaults to FontColor.WHITE.
        background_color (int, optional): Background color. Defaults to BackgroundColor.NOCOLOR.
        terminal_mode (int, optional): terminal mode. Defaults to TerminalMode.DEFAULT.

    Returns:
        str: A string with elaborate decoration.
    """
    check = __check(font_color, background_color, terminal_mode)
    if not check:
        print('\033[1;31;47mWARNING: Failure to set color!\033[0m')
        return print_str
    if background_color == BackgroundColor.NOCOLOR:
        background_color = ''
    else:
        background_color = ';' + str(background_color)
    res_str = '\033[{};{}{}m{}\033[0m'.format(terminal_mode, font_color, background_color, print_str)
    return res_str


def print_color(print_str: str, *,
                font_color: int = FontColor.WHITE,
                background_color: int = BackgroundColor.NOCOLOR,
                terminal_mode: int = TerminalMode.DEFAULT):
    """print a string with color

    Args:
        print_str (str): The str you want to modify.
        font_color (int, optional): Font color. Defaults to FontColor.WHITE.
        background_color (int, optional): Background color. Defaults to BackgroundColor.NOCOLOR.
        terminal_mode (int, optional): terminal mode. Defaults to TerminalMode.DEFAULT.

    """
    print(get_str_with_color(print_str, font_color=font_color, background_color=background_color,
                             terminal_mode=terminal_mode))


# r-g-b str
rstr = functools.partial(get_str_with_color, 
                    font_color=FontColor.RED, 
                    background_color=BackgroundColor.NOCOLOR, 
                    terminal_mode=TerminalMode.DEFAULT)

gstr = functools.partial(get_str_with_color, 
                    font_color=FontColor.GREEN, 
                    background_color=BackgroundColor.NOCOLOR, 
                    terminal_mode=TerminalMode.DEFAULT)

bstr = functools.partial(get_str_with_color, 
                    font_color=FontColor.BLUE, 
                    background_color=BackgroundColor.NOCOLOR, 
                    terminal_mode=TerminalMode.DEFAULT) 


# r-g-b print
rprint = functools.partial(print_color, 
                    font_color=FontColor.RED, 
                    background_color=BackgroundColor.NOCOLOR, 
                    terminal_mode=TerminalMode.DEFAULT)

gprint = functools.partial(print_color, 
                    font_color=FontColor.GREEN, 
                    background_color=BackgroundColor.NOCOLOR, 
                    terminal_mode=TerminalMode.DEFAULT)

bprint = functools.partial(print_color, 
                    font_color=FontColor.BLUE, 
                    background_color=BackgroundColor.NOCOLOR, 
                    terminal_mode=TerminalMode.DEFAULT)


def log_ex(msg, *args):
    """Logs a message to stdout."""
    if args:
        msg %= args
    gprint("[*] INFO: {}".format(msg))


def log_ex_highlight(msg, *args):
    """Logs a message to stdout."""
    if args:
        msg %= args
    print_color("[*] INFO: {}".format(msg), font_color=FontColor.GREEN, background_color=BackgroundColor.WHITE)


def log2_ex(msg, *args):
    """Logs an important message to stdout."""
    if args:
        msg %= args
    bprint("[#] IMPORTANT INFO: {}".format(msg))


def log2_ex_highlight(msg, *args):
    """Logs a message to stdout."""
    if args:
        msg %= args
    print_color("[#] IMPORTANT INFO: {}".format(msg), font_color=FontColor.BLUE, background_color=BackgroundColor.WHITE)


def errlog_ex(msg, *args):
    """Logs a message to stderr."""
    if args:
        msg %= args
    rprint("[!] ERROR: {}".format(msg))


def errlog_ex_highlight(msg, *args):
    """Logs a message to stdout."""
    if args:
        msg %= args
    print_color("[!] ERROR: {}".format(msg), font_color=FontColor.RED, background_color=BackgroundColor.WHITE)


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


def log_address_ex(variable:str, depth=2):
    """Log address from the variable's name by use of stack frame.

    Args:
        variable (str): The name.
        depth (int, optional): Stack frame depth. Defaults to 2.
    """
    assert isinstance(variable, str), "Variable must be a string!"
    assert depth >= 2, "depth error!"
    bf = sys._getframe()
    for i in range(depth - 1):
        bf = bf.f_back
    loc_var = bf.f_locals
    if variable not in loc_var:
        errlog_ex("Cannot find {}! Maybe the depth is wrong!".format(variable))
    else:
        var = loc_var[variable]
        assert isinstance(var, int), "The address is not int!"
        log_address(variable, var)


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
            if "/libc.so.6" in o or "/libc-2." in o:
                rp = os.path.realpath(o)
                break
    except:
        pass
    return rp


def one_gadget(so_path:str, more=False) -> int:
    """Get all one_gadget by exec one_gadget.

    Args:
        so_path (str): Libc.so path.
        more (bool, optional): Get more one_gadget or not. Defaults to False.

    Yields:
        int: Address of each one_gadget.
    """
    cmd_list = ["one_gadget", so_path]
    if more:
        cmd_list.append("-l")
        cmd_list.append("2")
    try:
        res = []
        out = subprocess.check_output(cmd_list, encoding='utf-8').split("\n")
        for o in out:
            if "exec" in o and "/bin/sh" in o:
                res.append(int16(o.split()[0]))
        return res
    except:
        errlog_exit("Cannot exec one_gadget, maybe you don't install one_gadget or filename is wrong!")


def one_gadget_binary(binary_path:str, more=False) -> int:
    """Get all one_gadget about a elf binary file.

    """
    binary_path = os.path.realpath(binary_path)
    rp = ldd_get_libc_path(binary_path)
    if rp:
        return one_gadget(rp, more)
    else:
        errlog_exit("Exec ldd {} fail!".format(binary_path))


#--------------------------------usefule function------------------------------
def u16_ex(data:(str, bytes)):
    assert isinstance(data, (str, bytes)), "wrong data type!"
    length = len(data)
    assert length <= 2, "len(data) > 2!"
    if isinstance(data, str):
        data = data.encode('utf-8')
    data = data.ljust(2, b"\x00")
    return unpack(data, 16)


def u32_ex(data:(str, bytes)):
    assert isinstance(data, (str, bytes)), "wrong data type!"
    length = len(data)
    assert length <= 4, "len(data) > 4!"
    if isinstance(data, str):
        data = data.encode('utf-8')
    data = data.ljust(4, b"\x00")
    return unpack(data, 32)
    

def u64_ex(data:(str, bytes)):
    length = len(data)
    assert length <= 8, "len(data) > 8!"
    assert isinstance(data, (str, bytes)), "wrong data type!"
    if isinstance(data, str):
        data = data.encode('utf-8')
    data = data.ljust(8, b"\x00")
    return unpack(data, 64)


def p8_ex(num:int):
    num &= 0xff
    return pack(num, word_size=8)


def p16_ex(num:int):
    num &= 0xffff
    return pack(num, word_size=16)


def p32_ex(num:int):
    num &= 0xffffffff
    return pack(num, word_size=32)


def p64_ex(num:int):
    num &= 0xffffffffffffffff
    return pack(num, word_size=64)


def p32_float(num:float, endian="little") -> bytes:
    if endian.lower() == "little":
        return struct.pack("<f", num)
    elif endian.lower() == "big":
        return struct.pack(">f", num)
    else:
        raise RuntimeError("Wrong endian!")
        

def p64_float(num:float, endian="little"):
    if endian.lower() == "little":
        return struct.pack("<d", num)
    elif endian.lower() == "big":
        return struct.pack(">d", num)
    else:
        raise RuntimeError("Wrong endian!")
    

def recv_libc_addr(p, *, bits=64, offset=0) -> int:
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
    m = p.recvuntil(contains, timeout=3)
    if contains not in m:
        raise RuntimeError("Cannot get libc addr")
    if bits == 32:
        return u32_ex(m[-4:]) - offset
    else:
        return u64_ex(m[-6:]) - offset


def get_flag_when_get_shell(p, use_cat:bool=True, contain_str:str="flag{"):
    """Get flag while get a shell

    Args:
        p (tube): Instance of tube in pwntools
        use_cat (bool, optional): Use cat /flag or not. Defaults to True.
        contain_str (str, optional): String contained in flag. Defaults to "flag{".
    """
    if use_cat:
        p.sendline("cat /flag")
    s = p.recvline_contains(contain_str)
    if contain_str.encode('utf-8') in s:
        log2_ex_highlight("{}".format(s))
    else:
        errlog_ex_highlight("Cannot get flag")


def get_segment_base_addr_by_proc_maps(pid:int, filename:str=None) -> dict:
    """Read /proc/pid/maps file to get base address. Return a dictionary obtaining keys: 'code',
    'libc', 'ld', 'stack', 'heap', 'vdso'.

    Args:
        pid (int): Pid of process.
        filename (str, optional): Filename to get code base address. Defaults to None.

    Returns:
        dict: All segment address. Key: str, Val: int.
    """
    assert isinstance(pid, int), "error type!"
    res = None
    try:
        res = subprocess.check_output(["cat", "/proc/{}/maps".format(pid)]).decode().split("\n")
    except:
        errlog_exit("cat /proc/{}/maps faild!".format(pid))
    _d = {}
    code_flag = 0
    libc_flag = 0
    ld_flag = 0

    for r in res:
        rc = re.compile(r"^([0123456789abcdef]{6,14})-([0123456789abcdef]{6,14})", re.S)
        rc = rc.findall(r)
        if len(rc) != 1 or len(rc[0]) != 2:
            continue
        start_addr = int(rc[0][0], base=16)
        end_addr = int(rc[0][1], base=16)
        if (filename is not None) and (not code_flag) and filename in r:
            code_flag = 1
            _d['code'] = start_addr
        elif (not libc_flag) and ("/libc-2." in r or "/libc.so" in r):
            libc_flag = 1
            _d['libc'] = start_addr
        elif (not ld_flag) and ("/ld-2." in r):
            ld_flag = 1
            _d['ld'] = start_addr
        elif "heap" in r:
            _d['heap'] = start_addr
        elif "stack" in r:
            _d['stack'] = start_addr  
        elif "vdso" in r:
            _d['vdso'] = start_addr
    return _d


if __name__ == "__main__":
    import doctest
    doctest.testmod(verbose=True)