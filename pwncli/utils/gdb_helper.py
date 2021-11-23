#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : gdb_helper.py
@Time    : 2021/11/23 23:47:26
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : Use gdb by python api when debugging
'''


from pwnlib import gdb

__all__ = [
    "kill_gdb",
    "execute_cmd_in_gdb",
    "set_pie_breakpoints",
    "tele_pie_content"
]


def kill_gdb(gdb_ins):
    """Kill gdb process."""
    if isinstance(gdb_ins, int):
        os.system("kill -9 {}".format(gdb_ins))
    else:
        gdb_ins.quit()


def execute_cmd_in_gdb(gdb_obj, cmd:str):
    """Execute commands in gdb, split commands by ';' or \\n."""
    cmd = cmd.replace(";", "\n")
    for x in cmd.splitlines():
        gdb_obj.execute(x)


def set_pie_breakpoints(gdb_obj, offset:int):
    """Set breakpoints by offset when binary's PIE enabled. Only support for 'pwndbg'."""
    execute_cmd_in_gdb(gdb_obj, "break *$rebase({})".format(offset))


def tele_pie_content(gdb_obj, offset:int, number=10):
    """Telescope content by offset when binary's PIE enabled. Only support for 'pwndbg'."""
    execute_cmd_in_gdb(gdb_obj, "telescope $rebase({}) {}".format(offset, number))