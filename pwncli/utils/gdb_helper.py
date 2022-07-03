#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : gdb_helper.py
@Time    : 2021/11/23 23:47:26
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : Use gdb by python api when debugging
'''

import os
from .exceptions import PwncliTodoException
from .misc import _in_tmux
from subprocess import check_output
import time

__all__ = [
    "kill_gdb",
    "execute_cmd_in_gdb",
    "set_pie_breakpoints",
    "tele_pie_content"
]

_TMUX_INFO = ""
def _get_tmux_info():
    if _in_tmux():
        if _TMUX_INFO:
            return _TMUX_INFO
        o = check_output("tmux display-message -p '#S:#I'")
        _TMUX_INFO =  o.decode() + ".1"
        return _TMUX_INFO
    return None

def kill_gdb(gdb_ins):
    """Kill gdb process."""
    if isinstance(gdb_ins, int):
        os.system("kill -9 {}".format(gdb_ins))
        time.sleep(0.2)
    else:
        gdb_ins.quit()


def execute_cmd_in_gdb(gdb_obj, cmd:str):
    """Execute commands in gdb, split commands by ';' or \\n."""
    cmd = cmd.replace(";", "\n")
    for x in cmd.splitlines():
        if x:
            if _get_tmux_info():
                os.system("tmux send -t {} \"{}\" Enter".format(_TMUX_INFO, x))
                time.sleep(0.1)
            else:
                gdb_obj.execute(x)


def set_pie_breakpoints(gdb_obj, offset:int):
    """Set breakpoints by offset when binary's PIE enabled. Only support for 'pwndbg'."""
    execute_cmd_in_gdb(gdb_obj, "break *$rebase({})".format(offset))


def tele_pie_content(gdb_obj, offset:int, number=10):
    """Telescope content by offset when binary's PIE enabled. Only support for 'pwndbg'."""
    execute_cmd_in_gdb(gdb_obj, "telescope $rebase({}) {}".format(offset, number))
