import sys
import os
import functools

__all__ = ['int16', 
           'int8', 
           'int2',
           'get_callframe_info',
           'log_address', 
           'FontColor', 
           'BackgroundColor', 
           'TerminalMode', 
           'get_str_with_color', 
           'print_color',
           'rstr',
           'gstr',
           'bstr',
           'rprint',
           'gprint',
           'bprint',
           'log',
           'log2',
           'errlog']

int16 = functools.partial(int, base=16)
int8 = functools.partial(int, base=8)
int2 = functools.partial(int, base=2)


def get_callframe_info(depth:int=2):
    """
    get callframe info
    :return: module_name, func_name, lineno
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


def log_address(desc:str, address:int):
    """
    print address by hex format
    :param desc: address description
    :param address: address value
    :return:
    """
    print("[+] {} ===> {}".format(desc, address))


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


def log(msg, *args):
    """Logs a message to stdout."""
    if args:
        msg %= args
    gprint("[***] INFO: {}".format(msg))


def log2(msg, *args):
    """Logs an important message to stdout."""
    if args:
        msg %= args
    bprint("[###] IMPORTANT INFO: {}".format(msg))


def errlog(msg, *args):
    """Logs a message to stderr."""
    if args:
        msg %= args
    rprint("[!!!] ERROR: {}".format(msg))
