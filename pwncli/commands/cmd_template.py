#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : cmd_template.py
@Time    : 2022/09/25 21:45:48
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : subcommand template
'''

import os
import click
import subprocess
from datetime import datetime
from pwncli.cli import pass_environ


def generate_exp(ctx, directory):
    content = """#!/usr/bin/env python3
# Date: {}
# Link: https://github.com/RoderickChan/pwncli
# Usage:
#     Debug : python3 exp.py debug elf-file-path -t -b malloc
#     Remote: python3 exp.py remote elf-file-path ip:port
#     Qemu  : python3 exp.py qemu ./pwn --tmux
#     Qemu  : python3 exp.py qemu ./pwn -L ./libs --tmux

from pwncli import *
cli_script()
{}

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

def cmd(i, prompt):
    sla(prompt, i)

def add():
    cmd('1')
    #......

def edit():
    cmd('2')
    #......

def show():
    cmd('3')
    #......

def dele():
    cmd('4')
    #......


ia()
"""
    exp_path = os.path.join(directory, "exp.py")
    if os.path.exists(exp_path):
        res = input("[*] {} exists, continue to overwrite? [y/n] ".format(exp_path))
        if res.lower().strip() != "y":
            print(res)
            ctx.vlog("template-command --> Stop creating the file: {}".format(exp_path))
            exit(0)

    set_remote_file = None
    for file in os.listdir(directory):
        if file.startswith("libc.so") or file.startswith("libc-2."):
            set_remote_file = os.path.join(directory, file)
            with open(set_remote_file, "rb") as f:
                data = f.read(4)
                if data != b"\x7fELF":
                    set_remote_file = None
                else:
                    set_remote_file = file
            break
    if set_remote_file:
        add_remote = "set_remote_libc('{}')".format(set_remote_file)
    else:
        add_remote = ""

    content = content.format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), add_remote)
    with open(exp_path, "wt", encoding="utf-8") as f:
        f.write(content)
    
    subprocess.run(["chmod", "+x", exp_path])
    ctx.vlog("template-command --> Generate exp file: {}".format(exp_path))


@click.command(name='template', short_help="Generate template file by pwncli.")
@click.argument('filetype', type=str, default=None, required=False, nargs=1)
@click.option("-d", "--dir", "directory", type=str, default=".", required=False, help="The directory to put files.")
@pass_environ
def cli(ctx, filetype, directory):
    ctx.verbose = 2
    if os.path.isdir(directory):
        ctx.abort("template-command --> {} not exists! please check your directory!".format(directory))
    if filetype == "kernel":
        pass
    else:
        generate_exp(ctx, directory)