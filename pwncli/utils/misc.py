import sys
import os
import functools
import subprocess
from pwn import unpack

int16 = functools.partial(int, base=16)
int8 = functools.partial(int, base=8)
int2 = functools.partial(int, base=2)

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


def errlog_highlight(msg, *args):
    """Logs a message to stdout."""
    if args:
        msg %= args
    print_color("[!] ERROR: {}".format(msg), font_color=FontColor.RED, background_color=BackgroundColor.WHITE)


def errlog_exit(msg, *args):
    """Logs a message to stderr and then exit."""
    errlog_ex(msg, *args)
    exit(-1)


def errlog_highlight_exit(msg, *args):
    """Logs a message to stderr and then exit."""
    errlog_highlight(msg, *args)
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
        out = subprocess.check_output(cmd_list, encoding='utf-8').split("\n")
        for o in out:
            if "execve" in o:
                yield int16(o.split()[0])
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

def u32_ex(data:(str, bytes)):
    length = len(data)
    assert length <= 4, "len(data) > 4!"
    assert isinstance(data, (str, bytes))
    if isinstance(data, str):
        data = data.encode('utf-8')
    data = data.ljust(4, b"\x00")
    return unpack(data, 32)
    

def u64_ex(data:(str, bytes)):
    length = len(data)
    assert length <= 8, "len(data) > 8!"
    assert isinstance(data, (str, bytes))
    if isinstance(data, str):
        data = data.encode('utf-8')
    data = data.ljust(8, b"\x00")
    return unpack(data, 64)
