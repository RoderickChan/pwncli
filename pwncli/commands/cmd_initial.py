import os.path
import re

import click
import sys
from pwncli.cli import pass_environ, _Inner_Dict
from pwn import ELF, wget
from subprocess import getstatusoutput

def _is_elf_file(filepath):
    if os.path.exists(filepath) and os.path.isfile(filepath):
        pass
    else:
        return False
    with open(filepath, "rb") as f:
        data = f.read(4)
        return data == b"\x7fELF"

def _left_str(s):
    return s.ljust(0x16, " ")

def _collect_info(ctx, info):
    ctx.vlog("-" * 70)
    ctx.vlog("Collect system info: ")
    glibc_info = ""
    status, output = getstatusoutput("cat /etc/issue")
    if status == 0:
        ctx.vlog(_left_str("Operating System") + " --->    {}".format(output[:-6]))

    status, output = getstatusoutput("ls -al /lib/x86_64-linux-gnu/libc.so.6")
    if status == 0:
        info.sys_libcfile = os.path.realpath("/lib/x86_64-linux-gnu/libc.so.6")
        ctx.vlog(_left_str("Default libc path") + " --->    {}".format(info.sys_libcfile))

        status, output = getstatusoutput("/lib/x86_64-linux-gnu/libc.so.6")
        if status == 0:
            glibc_info = re.findall("glibc [\d\.]+-\d+ubuntu[\d\.]+", output.splitlines()[0], re.I)[0]
            ctx.vlog(_left_str("Default libc version") +
                     " --->    {}".format(glibc_info))

    status, output = getstatusoutput("ls -al /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
    if status == 0:
        info.sys_ldfile = os.path.realpath("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
        ctx.vlog(_left_str("Default ld path") + " --->    {}".format(info.sys_ldfile))

    info.sys_glibcinfo = glibc_info


def _detect_file(ctx, info):
    ctx.vlog("-" * 70)
    ctx.vlog("Detect pwn context: ")
    libcfile = None
    glibcinfo = None
    ldfile = None
    elffile = None
    files = list(filter(_is_elf_file, os.listdir(".")))
    for f_ in files:
        if f_.startswith("libc"):
            libcfile = libcfile or f_
        elif f_.startswith("ld"):
            ldfile = ldfile or f_
        else:
            elffile = elffile or f_
    if libcfile:
        getstatusoutput("chmod +x " + libcfile)
        ctx.vlog(_left_str("Detect libc file") +
                 " --->    {}".format(libcfile))
        status, output = getstatusoutput("./"+libcfile)
        if status == 0:
            glibcinfo = re.findall("glibc [\d\.]+-\d+ubuntu[\d\.]+", output.splitlines()[0], re.I)[0]
            ctx.vlog(_left_str("Detect libc version") +
                     " --->    {}".format(glibcinfo))

    if ldfile:
        getstatusoutput("chmod +x " + ldfile)
        ctx.vlog(_left_str("Detect ld file") +
                 " --->    {}".format(ldfile))

    if elffile:
        getstatusoutput("chmod +x " + elffile)
        ctx.vlog(_left_str("Detect binary file") +
                 " --->    {}".format(elffile))
        os.system("checksec --file " + elffile)

    info.libcfile = libcfile
    info.ldfile = ldfile
    info.glibcinfo = glibcinfo
    info.elffile = elffile
    if not elffile:
        ctx.abort("cannot detect elf file!")


def _download_and_patch(ctx, info):
    if info.sys_glibcinfo and info.glibcinfo and info.sys_glibcinfo == info.glibcinfo:
        ctx.vlog("No need to patchelf...")
        info.patchelf = 0
        if not info.ldfile and info.sys_ldfile:
            getstatusoutput("cp -L {} .".format(info.sys_ldfile))
            info.ldfile = info.sys_ldfile

    if info.glibcinfo and info.patchelf != 0:
        info.patchelf = 1

    # TODO 1. get ldd info
    #      2. need patched?
    #      3. download deb/ddeb
    #      4. do patchlef
    status, output = getstatusoutput("ldd " + info.elffile)
    pass



@click.command(name='initial', short_help="pwn initial tool, inspired by https://github.com/io12/pwninit.")
@pass_environ
def cli(ctx):
    ctx.verbose = 2
    info = _Inner_Dict()
    _collect_info(ctx, info)
    _detect_file(ctx, info)
    _download_and_patch(ctx, info)
    os.system("pwncli template cli")