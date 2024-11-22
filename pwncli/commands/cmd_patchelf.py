#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : cmd_patchelf.py
@Time    : 2021/11/23 23:50:09
@Author  : Roderick Chan
@Email   : roderickchan@foxmail.com
@Desc    : patchelf subcommand
'''


import os
import re
import sys

import click
from pwn import which, yesno

from pwncli.cli import pass_environ
from pwncli.utils.config import try_get_config_data_by_key
from pwncli.utils.misc import _get_elf_arch_info


def get_arch_info_from_file(ctx, filepath):
    arch = _get_elf_arch_info(filepath)
    if arch in ("i386", "amd64"):
        return arch
    else:
        ctx.verrlog("patchelf-command --> Unsupported file, arch info:{}".format(arch))
        ctx.abort()


def _download_from_glibc_all_in_one(ctx, libc_so, archinfo, libc_dirname):
    download_info = ""
    with open(libc_so, "rt", encoding="utf-8", errors="ignore") as f:
        data = f.read()
    
    _match = re.search("GLIBC\s(\d\.\d\d-\dubuntu[\d\.]*)\)", data)
    if _match:
        download_info = _match.groups()[0] + "_" + archinfo
        download_path = os.path.split(libc_dirname)[0]
        cmd = "cd {} && {} {}".format(download_path, "./download", download_info)
        os.system(cmd)
        ctx.vlog("patchelf-command --> Exec cmd: {}".format(cmd))
        return download_info[:4]
    else:
        ctx.abort("patchelf-command --> Cannot get glibc version, please specify libc_version or check your libc.so file: {}".format(libc_so))
    

@click.command(name='patchelf', short_help="Patchelf executable file with glibc-all-in-one.")
@click.argument('filename', type=str, required=True, nargs=1)
@click.argument("libc-version", required=False, nargs=1, type=str)
@click.option('-b', '--back', '--back-up', "back_up", is_flag=True, help="Backup target file or not.")
@click.option('-f', '--filter', '--filter-string', "filter_string", default=[], type=str, multiple=True, help="Add filter condition.")
@click.option('-s', '-l', '--libc-so', "libc_so", type=click.Path(exists=True, file_okay=True), default=".", required=False, help="The libc.so.6 file, libc_version will be ignored when libc.so.6 file specified.")
@click.option('-v', '--verbose', count=True, help="Show more info or not.")
@pass_environ
def cli(ctx, filename, libc_version, back_up, filter_string, verbose, libc_so):
    """FILENAME: ELF executable filename.\n
    LIBC_VERSION: Libc version.

    \b
    pwncli patchelf ./filename 2.23 -b

    To execute:

        patchelf --set-interpreter ./ld-2.23.so ./pwn

        patchelf --replace-needed libc.so.6 ./libc-2.23.so ./pwn
    """
    if not ctx.verbose:
        ctx.verbose = verbose
    if verbose:
        ctx.vlog("patchelf-command --> Open 'verbose' mode")
    
    # libs-dirname
    libs_dirname = try_get_config_data_by_key(ctx.config_data, "patchelf", "libs_dir")
    if not libs_dirname:
        libs_dirname = os.path.join(os.environ['HOME'],"glibc-all-in-one/libs")
    
    if libs_dirname.startswith("~"):
        libs_dirname = os.path.expanduser(libs_dirname)
    
    libs_dirname = os.path.abspath(os.path.realpath(libs_dirname)).rstrip("/")
    
    # check libc_dirname
    if not os.path.exists(libs_dirname) or not os.path.isdir(libs_dirname):
        ctx.verrlog("patchelf-command --> Libs dir '{}' not exists!".format(libs_dirname))
        if yesno("clone glibc-all-in-one from github?"):
            if 0 != os.system("git clone https://github.com/matrix1001/glibc-all-in-one.git ~/glibc-all-in-one"):
                ctx.abort("patchelf-command --> Execute cmd: git clone https://github.com/matrix1001/glibc-all-in-one.git ~/ failed!")
            ctx.vlog2("patchelf-command --> Execute cmd: git clone https://github.com/matrix1001/glibc-all-in-one.git ~/ success!")
            libs_dirname = os.path.join(os.environ['HOME'],"glibc-all-in-one/libs")
        else:
            sys.exit(1)
    
    if not libs_dirname.endswith("glibc-all-in-one/libs"):
        ctx.abort("patchelf-command --> Unsupported libc_dirname, must end with glibc-all-in-one/libs.")

    ctx.vlog("patchelf-command --> Now libs_dirname used is: {}".format(libs_dirname))

    # check file name
    if not os.path.isfile(os.path.abspath(filename)):
        ctx.abort("patchelf-command --> Filename '{}' error!".format(filename))
    
    # check patchelf
    if not which('patchelf'):
        ctx.abort("patchelf-command --> Cannot find 'patchelf', please install it first!")
    
    filename = os.path.abspath(filename)
    archinfo = get_arch_info_from_file(ctx, filename)

    if os.path.exists(libc_so) and os.path.isfile(libc_so):
        ctx.vlog2("patchelf-command --> Libc_so is specified, libc_version would be reset.")
        libc_version = _download_from_glibc_all_in_one(ctx, libc_so, archinfo, libs_dirname)

    # check libc_version
    if not re.search("^\d\.\d\d$", libc_version):
        ctx.abort("patchelf-command --> Invalid libc_version: {}".format(libc_version))

    def _filter_dir(_d):
        for _i in filter_string:
                if _i not in _d:
                    return False
        if (archinfo in _d) and (os.path.isdir(os.path.join(libs_dirname, _d))):
            return True
        return False

    subdirs = list(filter(_filter_dir, os.listdir(libs_dirname)))
    if not subdirs or len(subdirs) == 0:
        ctx.abort("patchelf-command --> Do not find the matched dirctories in {}, with libc_version: {}, filter-string:{}".format(libs_dirname, libc_version, filter_string))

    subdirs.sort()
    
    has_versions = [x[:4] for x in subdirs]
    
    if not has_versions or len(has_versions) == 0 or libc_version not in has_versions:
        ctx.abort("patchelf-command --> Do not have the libc version of {}, only have {}!".format(libc_version, has_versions))
    
    # backup first
    if back_up:
        cmd = "cp {} {}".format(filename, filename+".bk")
        ctx.vlog("patchelf-command --> Backup file named: {}".format(filename+".bk"))
        os.system(cmd)
    
    # execute patchelf
    subdirname = subdirs[has_versions.index(libc_version)]
    last_dirname = os.path.join(libs_dirname, subdirname)
    ctx.vlog("patchelf-command --> The dirname of libs using by patchelf: {}".format(last_dirname))

    ldfile_path = os.path.join(last_dirname, 'ld-{}.so'.format(libc_version))
    if not os.path.exists(ldfile_path):
        ldfile_path = os.path.join(last_dirname, 'ld-linux-x86-64.so.2')
        if not os.path.exists(ldfile_path):
            ctx.abort("patchelf-command --> The ld file: {} not exists!".format(ldfile_path))
    
    libcfile_path = os.path.join(last_dirname, 'libc-{}.so'.format(libc_version))
    if not os.path.exists(libcfile_path):
        libcfile_path = os.path.join(last_dirname, 'libc.so.6')
        if not os.path.exists(libcfile_path):
            ctx.abort("patchelf-command --> The libc file: {} not exists!".format(libcfile_path))
    
    cmd1 = "patchelf --set-interpreter {} {}".format(ldfile_path, filename)
    ctx.vlog("patchelf-command --> Execute cmd: {}".format(cmd1))
    os.system(cmd1)

    cmd2 = "patchelf --replace-needed libc.so.6 {} {}".format(libcfile_path, filename)
    ctx.vlog("patchelf-command --> Execute cmd: {}".format(cmd2))
    os.system(cmd2)

    print("The output of ldd:")
    os.system("ldd {}".format(filename))
    
