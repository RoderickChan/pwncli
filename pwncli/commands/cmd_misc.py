#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : cmd_misc.py
@Time    : 2022/12/12 15:41:17
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : None
'''


import os
import tempfile
import subprocess
import shlex

import click
from pwn import which, listen, context, wget
from pwncli.cli import AliasedGroup, _set_filename, pass_environ, _Inner_Dict


@click.command(cls=AliasedGroup, name='misc', short_help="Misc of useful sub-commands.")
@pass_environ
def cli(ctx):
    ctx.verbose = 2  # set verbose


@cli.command(name="gadget", short_help="Get all gadgets using ropper and ROPgadget, and then store them in files.")
@click.argument('filename', type=str, default=None, required=False, nargs=1)
@click.option('-a', '--all', '--all-gadgets', "all_gadgets", is_flag=True, show_default=True, help="Get all gadgets and don't remove duplicates.")
@click.option('-d', '--dir', '--directory', "directory", type=click.Path(exists=True, dir_okay=True), default=".", required=False, help="The directory to save files.")
@click.option('-o', '--opcode', "opcode", type=str, default="", required=False, help="The opcode mode.")
@click.option('-n', '--depth', '--count', "depth", type=int, default=-1, required=False, help="The depth of the gadgets.")
@pass_environ
def get_gadgets(ctx, filename, all_gadgets, directory, depth, opcode):
    """
    FILENAME: The binary file name.
    
    \b
    pwncli misc gadget ./pwn -d ./gadgets -a -n 20
    
    pwncli m g ./pwn -n 10
    """
    _set_filename(ctx, filename)

    if not ctx.get('filename'):
        ctx.abort(
            "gadget-command ---> No filename, please specify the binary file.")

    ropper_path = which("ropper")
    ropgadget_path = which("ROPgadget")
    rp_path = which("rp-lin-x64")

    if len(opcode) > 0:
        opcode = opcode.strip()
        opcode = opcode.strip("'")
        opcode = opcode.strip("\"")

        len_ = len(opcode)
        if len_ > 0 and len_ % 2 == 0:
            pass
        else:
            ctx.abort("gadget-command ---> The opcode is invalid.")

        if rp_path:
            n_ = ""
            for i in range(0, len_, 2):
                n_ += "\\x"
                n_ += opcode[i:i+2]
            opcode = n_
            cmd = "rp-lin-x64 -f {} --search-hexa \"{}\"".format(
                filename, opcode)
        elif ropgadget_path:
            cmd = "ROPgadget --binary {} --opcode {}".format(filename, opcode)
        elif ropper_path:
            cmd = "ropper -f {} --opcode {}".format(filename, opcode)
        else:
            ctx.abort(
                "gadget-command ---> No rop tools exists, please install one.")
        ctx.vlog("gadget-command ---> Exec cmd: {}".format(cmd))
        os.system(cmd)
        return

    if not os.path.isdir(directory):
        ctx.abort("gadget-command ---> The 'directory' is invalid.")

    if not rp_path:
        res = input(
            "Install rp-lin-x64 from https://github.com/0vercl0k/rp/releases/download/v2.0.2/rp-lin-x64? [y/n]")
        if res.strip() == "y":
            try:
                wget("https://github.com/0vercl0k/rp/releases/download/v2.0.2/rp-lin-x64",
                     timeout=300, save=True)
                bin_path = "$HOME/.local/bin" if os.getuid() != 0 else "/usr/local/bin"

                ctx.vlog(
                    "gadget-command ---> Exec cmd: {}".format("chmod +x rp-lin-x64"))
                os.system("chmod +x rp-lin-x64")
                cmd = "mv rp-lin-x64 {}".format(bin_path)

                ctx.vlog("gadget-command ---> Exec cmd: {}".format(cmd))
                os.system(cmd)
                if which("rp-lin-x64"):
                    rp_path = 1
                else:
                    rp_path = 0
            except:
                ctx.verrlog("gadget-command ---> Download rp-lin-x64 error!")
    ps = []
    if rp_path:
        cmd = "rp-lin-x64 -f {} ".format(filename)
        if not all_gadgets:
            cmd += " --unique "
        if depth > 0:
            cmd += " -r {} ".format(depth)
        else:
            cmd += " -r 6 "
        store_file = "{}".format(os.path.join(
            directory, "rp_gadgets-" + os.path.split(ctx.get('filename'))[1]))
        ctx.vlog(
            "gadget-command ---> Exec cmd: {} and store in {}".format(cmd, store_file))
        p = subprocess.Popen(shlex.split(cmd), stdout=open(
            store_file, "wt", encoding='utf-8', errors='ignore'))
        # ps.append(p)

    if ropgadget_path:
        cmd = "ROPgadget --binary {}".format(filename)
        if all_gadgets:
            cmd += " --all"
        if depth > 0:
            cmd += " --depth {}".format(depth)
        store_file = "{}".format(os.path.join(
            directory, "ropgadget_gadgets-" + os.path.split(ctx.get('filename'))[1]))
        ctx.vlog(
            "gadget-command ---> Exec cmd: {} and store in {}".format(cmd, store_file))
        p = subprocess.Popen(shlex.split(cmd), stdout=open(
            store_file, "wt", encoding='utf-8', errors='ignore'))
        # ps.append(p)

    if ropper_path and (not ropgadget_path):
        cmd = "ropper -f {} --nocolor".format(filename)
        if all_gadgets:
            cmd += " --all"
        if depth > 0:
            cmd += " --inst-count {}".format(depth)
        store_file = "{}".format(os.path.join(
            directory, "ropper_gadgets-" + os.path.split(ctx.get('filename'))[1]))
        ctx.vlog(
            "gadget-command ---> Exec cmd: {} and store in {}".format(cmd, store_file))
        p = subprocess.Popen(shlex.split(cmd), stdout=open(
            store_file, "wt", encoding='utf-8', errors='ignore'))
        ps.append(p)

    for p in ps:
        p.wait()
        p.terminate()


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
            exit(0)
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


@cli.command(name="listen", short_help="Listen on a port and spawn a program when connected.")
@click.option('-l', '--listen-once', "listen_one", is_flag=True, help="List once.")
@click.option('-L', '--listen-forever', "listen_forever", is_flag=True, help="List forever.")
@click.option('-p', '--port', "port", type=int, default=13337, help="List port.")
@click.option('-t', '--timeout', "timeout", type=int, default=300, help="List port.")
@click.option('-e', '--executable', "executable", type=str, default="", help="Executable file path to spawn.")
@click.option('-v', '--verbose', count=True, help="Show more info or not.")
@pass_environ
def listen_(ctx, listen_one, listen_forever, port, timeout, executable, verbose):
    """
    \b
    pwncli misc listen -l
    pwncli misc listen -L
    pwncli misc listen -l -p 10001
    pwncli misc listen -l -vv -p 10001
    pwncli misc listen -l -vv -p 10001 -e /bin/bash # socat tcp-l:10001,fork exec:/bin/bash

    pwncli m l -l
    """
    if port < 1025:
        port = 13337
        ctx.vlog("listen-command ---> port must be larger than 1024.")
    if timeout < 1:
        timeout = 300
        ctx.vlog("listen-command ---> timeout must be a positive.")

    if executable:
        executable = executable.split()
        for exe_ in executable:
            if exe_:
                if os.path.exists(exe_) and os.path.isfile(exe_) and os.access(exe_, os.X_OK):
                    ctx.vlog2(
                        "listen-command ---> executable file check pass!.")
                else:
                    ctx.abort(
                        "listen-command ---> executable file check failed! path: {}".format(exe_))
    if (listen_one and listen_forever) or (not listen_one and not listen_forever):
        ctx.abort(
            "listen-command ---> listen_once and listen_forever cannot be specified or canceled at the same time")
    args = _Inner_Dict()
    args.listen_one = listen_one
    args.listen_forever = listen_forever
    args.port = port
    args.timeout = timeout
    args.executable = executable
    args.verbose = verbose
    for k, v in args.items():
        ctx.vlog("listen-command --> Set '{}': {}".format(k, v))

    if verbose:
        context.log_level = "debug"
    else:
        context.log_level = "error"

    def _f():
        ser = listen(port)
        if executable:
            ser.spawn_process(executable)
        ser.wait_for_connection()
        try:
            while ser.recv(4096, timeout=timeout):
                pass
        except:
            pass
        ser.close()

    while listen_forever:
        _f()
    else:
        _f()
