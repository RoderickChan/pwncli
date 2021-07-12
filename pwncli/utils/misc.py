import sys
import os
import functools
from pwncli.cli import _treasure, gift

__all__ = ['int16', 'int8', 'int2', 'stop', 'log_address', 'FontColor', 'BackgroundColor', 'TerminalMode', 'get_str_with_color', 'print_color']

int16 = functools.partial(int, base=16)
int8 = functools.partial(int, base=8)
int2 = functools.partial(int, base=2)

def stop():
    """
    stop the program and print the caller's info
    :return:
    """
    if _treasure.get('no_stop', None):
        return

    func_name = ''
    mode_name = ''
    lineno, pid = -1, -1
    try:
        # try to get file line number
        f = sys._getframe().f_back
        mode_name = os.path.split(f.f_code.co_filename)[1]
        func_name = f.f_code.co_name
        lineno = f.f_lineno
    except:
        lineno = -1

    # try to get pid
    if gift.get('io', None):
        pid = gift['io'].proc.pid


    msg = '[*] stop'
    if lineno != -1:
        msg += ' at module: {}  function: {}  line: {}'.format(mode_name, func_name, lineno)
    if pid != -1:
        msg += '  local pid: {}'.format(pid)
    input(msg)


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
    b2 = (
                     background_color >= BackgroundColor.BLACK and background_color <= BackgroundColor.WHITE) or background_color == BackgroundColor.NOCOLOR
    b3 = (
                terminal_mode >= TerminalMode.DEFAULT and terminal_mode <= TerminalMode.INVISIBLE and terminal_mode != 2 and terminal_mode != 3 and terminal_mode != 6)
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
