#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : cmd_patchelf.py
@Time    : 2021/11/23 23:50:09
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : patchelf subcommand
'''


import click
import sys
import os
from pwncli.cli import pass_environ
from pwn import which


def get_arch_info_from_file(filepath):
    from subprocess import check_output
    out = check_output(["file", filepath])
    if b"32-bit" in out:
        return 'i386'
    elif b"64-bit" in out:
        return 'amd64'
    else:
        ctx.verrlog("patchelf-command --> Unsupported file, arch info:{}".format(out.decode()))
        ctx.abort()


@click.command(name='patchelf', short_help="Patchelf executable file using glibc-all-in-one.")
@click.argument('filename', type=str, required=True, nargs=1)
@click.argument("libc-version", required=True, nargs=1, type=str)
@click.option('-b', '--back-up', is_flag=True, help="Backup target file or not.")
@click.option('-f', '--filter-string', default=[], type=str, multiple=True, help="Add filter condition.")
@pass_environ
def cli(ctx, filename, libc_version, back_up, filter_string):
    """FILENAME: ELF executable filename.\n
    LIBC_VERSION: Libc version.

    \b
    pwncli patchelf ./filename 2.29 -b
    """
    ctx.verbose = 2
    
    # default libs-dirname
    libc_dirname = os.path.expanduser("~/glibc-all-in-one/libs")
    
    # check libc_dirname
    if not os.path.isdir(libc_dirname):
        ctx.abort("patchelf-command --> Libs dir '{}' not exists!".format(libc_dirname))
    
    # check file name
    if not os.path.isfile(os.path.abspath(filename)):
        ctx.abort("patchelf-command --> Filename '{}' error!".format(filename))
    
    # check patchelf
    if not which('patchelf'):
        ctx.verrlog("patchelf-command --> Cannot find 'patchelf', please install it first!")
        ctx.abort()
        
    filename = os.path.abspath(filename)
    archinfo = get_arch_info_from_file(filename)
    def _filter_dir(_d):
        for _i in filter_string:
                if _i not in _d:
                    return False
        if (archinfo in _d) and (os.path.isdir(os.path.join(libc_dirname, _d))):
            return True
        return False

    subdirs = list(filter(_filter_dir, os.listdir(libc_dirname)))
    if not subdirs or len(subdirs) == 0:
        ctx.verrlog("patchelf-command --> Do not find the matched dirctories in {}, with libc_version: {}, filter-string:{}!".format(libc_dirname, libc_version, filter_string))
        ctx.abort()

    subdirs.sort()
    
    has_versions = [x[:4] for x in subdirs]
    
    if not has_versions or len(has_versions) == 0 or libc_version not in has_versions:
        ctx.verrlog("patchelf-command --> Do not have the libc version of {}, only have {}!".format(libc_version, has_versions))
        ctx.abort()

    # backup first
    if back_up:
        cmd = "cp {} {}".format(filename, filename+".bk")
        ctx.vlog("patchelf-command --> Backup file named: {}".format(filename+".bk"))
        os.system(cmd)
    
    # execute patchelf
    subdirname = subdirs[has_versions.index(libc_version)]
    last_dirname = os.path.join(libc_dirname, subdirname)
    ctx.vlog("patchelf-command --> The dirname of libs using by patchelf: {}".format(last_dirname))

    cmd1 = "patchelf --set-interpreter {} {}".format(os.path.join(last_dirname, 'ld-{}.so'.format(libc_version)), filename)
    ctx.vlog("patchelf-command --> Execute cmd: {}".format(cmd1))
    os.system(cmd1)

    cmd2 = "patchelf --replace-needed libc.so.6 {} {}".format(os.path.join(last_dirname, 'libc-{}.so'.format(libc_version)), filename)
    ctx.vlog("patchelf-command --> Execute cmd: {}".format(cmd2))
    os.system(cmd2)

    ctx.vlog("patchelf-command --> Use ldd to check whether execute 'patchelf' successfully!\n")
    print("The output of ldd:")
    os.system("ldd {}".format(filename))
    