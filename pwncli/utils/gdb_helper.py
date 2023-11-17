#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : gdb_helper.py
@Time    : 2021/11/23 23:47:26
@Author  : Roderick Chan
@Email   : roderickchan@foxmail.com
@Desc    : Use gdb by python api when debugging
'''

import os
import tempfile
import time
from subprocess import check_output

from pwnlib.atexit import register

from .decorates import always_success, cache_nonresult, limit_calls
from .misc import _in_tmux

__all__ = [
    "kill_gdb",
    "execute_cmd_in_gdb",
    "set_pie_breakpoints",
    "tele_pie_content",
    "add_struct_by_file",
    "add_show_struct_command",
    "add_struct_by_member"
]

@always_success()
def _unlink_file(f):
    os.unlink(f)

def _unlink_files(*fs):
    for f in fs:
        _unlink_file(f)

@limit_calls(1, False)
def _sleep_0_2():
    time.sleep(0.2)

@cache_nonresult
def _get_tmux_info():
    if _in_tmux():
        o = check_output("tmux display-message -p '#S:#I'", shell=True).strip()
        return o.decode() + ".1"
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
                _sleep_0_2()
                os.system("tmux send -t {} \"{}\" Enter".format(_get_tmux_info(), x))
                time.sleep(0.1)
            else:
                gdb_obj.execute(x)

# name: type
def add_struct_by_member(gdb_obj, struct_name, add_show_cmd=False, *struct_mems, **struct_memskw):
    """
    add_struct_by_member(gdb_obj, "struct student", True, "char *teachers[10]", name="i8 *", id="u64", grade="size_t")
    """
    body = ""
    for k in struct_mems:
        body += "{};\n".format(k)
    for k, v in struct_memskw.items():
        body += "{} {};\n".format(v, k)
    var_name = struct_name.replace(" ", "_") + "_var"
    if "struct " in struct_name:
        template = """
%s {
    %s
} %s;
""" % (struct_name, body, var_name)
    else:
        template = """
typedef struct {
    %s
} %s;

%s %s;
""" % (body, struct_name, struct_name, var_name)
    add_struct_by_file(gdb_obj, template, add_show_cmd, struct_name)
    


def add_struct_by_file(gdb_obj, file_content, add_show_cmd=False, *struct_names):
    file_content = """
typedef signed char __int8_t;
typedef unsigned char __uint8_t;
typedef signed short int __int16_t;
typedef unsigned short int __uint16_t;
typedef signed int __int32_t;
typedef unsigned int __uint32_t;
#if __WORDSIZE == 64
typedef signed long int __int64_t;
typedef unsigned long int __uint64_t;
typedef __uint64_t size_t;
#else
__extension__ typedef signed long long int __int64_t;
__extension__ typedef unsigned long long int __uint64_t;
typedef __uint32_t size_t;
#endif

typedef __uint8_t uint8_t;
typedef __uint16_t uint16_t;
typedef __uint32_t uint32_t;
typedef __uint64_t uint64_t;

typedef __int8_t int8_t;
typedef __int16_t int16_t;
typedef __int32_t int32_t;
typedef __int64_t int64_t;

typedef __int8_t i8;
typedef __int16_t i16;
typedef __int32_t i32;
typedef __int64_t i64;

typedef __uint8_t u8;
typedef __uint16_t u16;
typedef __uint32_t u32;
typedef __uint64_t u64;

typedef __uint8_t BYTE;
typedef __uint8_t byte;

""" + file_content
    file = tempfile.NamedTemporaryFile("wt", delete=False, suffix=".c")
    file.write(file_content)
    file.flush()
    so = file.name + ".so"
    sym = file.name + ".symbol"
    register(_unlink_files, file.name, so, sym)
    check_output("gcc %s -fPIC -shared -o %s -ggdb -O0" % (file.name, so), shell=True)
    check_output("objcopy --only-keep-debug %s %s" % (so, sym), shell=True)
    execute_cmd_in_gdb(gdb_obj, "add-symbol-file %s" % sym)
    if add_show_cmd:
        add_show_struct_command(gdb_obj, *struct_names)
    

def add_show_struct_command(gdb_obj, *struct_names):
    """
    eg: add_show_struct_command(gdb_obj, "struct Student", "Point_t")
    """
    file = tempfile.NamedTemporaryFile("wt", delete=False, suffix=".py")
    register(_unlink_files, file.name)
    file_content = ""
    for struct in struct_names:
        print(struct, struct_names)
        name = struct.strip()
        if not name:
            continue
        if "struct " in name:
            name = name.split()[1]
        cmd = """
import gdb

class PwncliShow%s(gdb.Command):
    def __init__(self):
        super(self.__class__, self).__init__("pwncli_show_%s", gdb.COMMAND_DATA)
    
    def invoke(self, args, from_tty):
        argv = gdb.string_to_argv(args)
        for arg in argv:
            gdb.execute("p /x *(%s*){}".format(arg))

PwncliShow%s()        

""" % (name, name, struct, name)
        
        file_content += cmd
    file.write(file_content)
    file.flush()
    execute_cmd_in_gdb(gdb_obj, "source %s" % file.name)
        

def set_pie_breakpoints(gdb_obj, offset:int):
    """Set breakpoints by offset when binary's PIE enabled. Only support for 'pwndbg'."""
    execute_cmd_in_gdb(gdb_obj, "break *$rebase({})".format(offset))


def tele_pie_content(gdb_obj, offset:int, number=10):
    """Telescope content by offset when binary's PIE enabled. Only support for 'pwndbg'."""
    execute_cmd_in_gdb(gdb_obj, "telescope $rebase({}) {}".format(offset, number))
