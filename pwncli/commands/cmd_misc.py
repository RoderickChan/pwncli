#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : cmd_misc.py
@Time    : 2022/12/12 15:41:17
@Author  : Roderick Chan
@Email   : roderickchan@foxmail.com
@Desc    : None
'''


import os
import sys
import tempfile

import click
from pwn import which

from ..cli import AliasedGroup, _Inner_Dict, _set_filename, pass_environ


@click.command(cls=AliasedGroup, name='misc', short_help="Misc of useful sub-commands.")
@pass_environ
def cli(ctx):
    ctx.verbose = 2  # set verbose


@cli.command(name="setgdb", short_help="Copy gdbinit files from and set gdb-scripts for current user.")
@click.option('-g', '--generate-script', "generate_script", is_flag=True, show_default=True, help="Generate the scripts of gdb-gef/gdb-pwndbg/gdb-peda in /bin or $HOME/.local/bin or not.")
@click.confirmation_option(prompt="Copy gdbinit files from pwncli/conf/.gdbinit-* to user directory?", expose_value=False)
@pass_environ
def copy_gdbinit(ctx, generate_script):
    """
    \b
    pwncli misc setgdb 

    """
    if ctx.platform != "linux":
        ctx.abort("setgdb-command ---> This command can only be used in linux.")
    predir = os.path.join(os.environ['HOME'], ".local", "bin")
    if os.getuid() == 0:
        predir = "/bin"

    gdbinit_file_path = os.path.join(ctx.pwncli_path, "conf/.gdbinit-")

    if generate_script:
        for name in ("pwndbg", "gef", "peda"):
            _cur_path = os.path.join(predir, "gdb-{}".format(name))
            write_data = "#!/bin/sh\n"
            write_data += 'cat > ~/.gdbinit << "EOF"\n'
            with open(gdbinit_file_path+name, "rt", encoding="utf-8", errors="ignore") as gdbinitf:
                write_data += gdbinitf.read()
            if os.path.isfile(os.path.join(os.getenv('HOME'), ".d2d.py")):
                write_data += "\nsource ~/.d2d.py\n"
            write_data += '\nEOF\n'
            write_data += "\nexec gdb \"$@\"\n"
            with open(_cur_path, "wt", encoding="utf-8", errors="ignore") as file:
                file.write(write_data)
                ctx.vlog(
                    "setgdb-command ---> Generate {} success.".format(_cur_path))
            os.system("chmod 755 {}".format(_cur_path))


# add display struct info
@cli.command(name="dstruct", short_help="Display struct info by gdb.")
@click.argument('filename', type=str, default=None, required=False, nargs=1)
@click.option('-s', '--save-all', "save_all", is_flag=True, show_default=True, help="Save all struct info or not.")
@click.option('-d', '--dir', '--directory', "directory", type=click.Path(exists=True, dir_okay=True), default=".", required=False, help="The directory to save files.")
@click.option('-n', '--name',  "name", default=[], type=str, multiple=True, show_default=True, help="The name of struct you want to show.")
@pass_environ
def export_struct_info(ctx, filename, save_all, directory, name):
    """
    FILENAME: The binary file name.
    
    \b
    pwncli misc dstruct ./vmlinux -n cred -n tty_struct
    
    pwncli m d ./vmlinux -s
    """
    _set_filename(ctx, filename)
    if not ctx.get('filename'):
        ctx.abort(
            "dstruct-command ---> No filename, please specify the binary file.")

    if not which("gdb"):
        ctx.abort("dstruct-command ---> No gdb, please install gdb first.")

    write_path = ""
    if save_all:
        write_path = os.path.join(
            directory, os.path.basename(filename)+"_struct_info.txt")

    # step 1: get struct info by gdb
    struct_name = []
    with tempfile.NamedTemporaryFile(mode="a+t") as tf:
        # print(tf.name)
        cmd = "gdb -q {} -batch -ex 'set logging file {}' -ex 'set logging on' -ex 'info types' -ex 'set logging off' >/dev/null".format(
            filename, tf.name)
        ctx.vlog("dstruct-command ---> Exec cmd: {}".format(cmd))
        os.system(cmd)

        for line in tf:
            line = line.strip().rstrip(";")
            if line.startswith("struct "):
                struct_name.append(line)

    name = ["struct " + n.strip() if not n.strip().startswith("struct")
            else n.strip() for n in name]
    for n in name:
        if n not in struct_name:
            ctx.abort(
                "dstruct-command ---> Invalid name: {}, cannot find this struct.".format(n))

    # default to print all
    if len(name) == 0:
        res = input(
            "[*] No struct name is given, display all struct info in {}, continue? [y/n]".format(filename)).strip().lower()
        if res != "y":
            sys.exit(0)
        name = struct_name

    # step 2: show info
    with tempfile.NamedTemporaryFile(mode="w+t", suffix=".py") as tf:
        cmd = "gdb -q {} -batch".format(filename)
        if write_path:
            cmd += " -ex 'set logging file {}' -ex 'set logging on'".format(
                write_path)
        cmd += " -ex 'source {}'".format(tf.name)
        if write_path:
            cmd += " -ex 'set logging off'"

        content = """
import gdb

class MyGetOffset(gdb.Command):
    def __init__(self):
        super(self.__class__, self).__init__("get-offset", gdb.COMMAND_DATA)
    
    def invoke(self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) != 1:
            raise GdbError('get-offset need only 1 argument.')
        struct_type = gdb.lookup_type(argv[0])
        print("[{{}}] size: {{}}  {{}}".format(argv[0], struct_type.sizeof, hex(struct_type.sizeof)))
        print(" {{")
        for field in struct_type.fields():
            print("  {{}} ---> {{}}".format(hex(field.bitpos // 8), field.name))
        print(" }}")
        print("\\n"+"-"*60+"\\n")

MyGetOffset()

for s in {}:
    try:
        gdb.execute("pt /o {{}}".format(s))
        print("\\n"+"-"*60+"\\n")
    except:
        try:
            gdb.execute('get-offset "{{}}"'.format(s))
        except:
            pass
        pass
""".format(repr(name))
        tf.write(content)
        tf.flush()

        # os.system(f"cat {tf.name}")
        ctx.vlog("dstruct-command ---> Exec cmd: {}".format(cmd))
        os.system(cmd)
