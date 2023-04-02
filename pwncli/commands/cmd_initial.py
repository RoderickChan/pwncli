import os
import re
import sys
from subprocess import getstatusoutput

import click
from pwn import ELF, wget

from pwncli.cli import _Inner_Dict, pass_environ


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


def _make_template_exit():
    os.system("pwncli template cli")
    sys.exit(0)


def _collect_info(ctx, info):
    ctx.vlog("-" * 70)
    ctx.vlog("Collect system info: ")
    glibc_info = ""
    status, output = getstatusoutput("cat /etc/issue")
    if status == 0:
        ctx.vlog(_left_str("Operating System") +
                 " --->    {}".format(output[:-6]))

    status, output = getstatusoutput("ls -al /lib/x86_64-linux-gnu/libc.so.6")
    if status == 0:
        info.sys_libcfile = os.path.realpath("/lib/x86_64-linux-gnu/libc.so.6")
        ctx.vlog(_left_str("Default libc path") +
                 " --->    {}".format(info.sys_libcfile))

        status, output = getstatusoutput("/lib/x86_64-linux-gnu/libc.so.6")
        if status == 0:
            glibc_info = re.findall(
                "glibc [\d\.]+-\d+ubuntu[\d\.]+", output.splitlines()[0], re.I)[0]
            ctx.vlog(_left_str("Default libc version") +
                     " --->    {}".format(glibc_info))

    status, output = getstatusoutput(
        "ls -al /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
    if status == 0:
        info.sys_ldfile = os.path.realpath(
            "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
        ctx.vlog(_left_str("Default ld path") +
                 " --->    {}".format(info.sys_ldfile))

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
            if "musl" in output:
                _make_template_exit()  # musl
            glibcinfo = re.findall(
                "glibc [\d\.]+-\d+ubuntu[\d\.]+", output.splitlines()[0], re.I)[0]
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
    elf = ELF(elffile, checksec=False)
    if elf.arch != "amd64":
        ctx.abort("only support amd64!")

    if elf.statically_linked:
        _make_template_exit()
    info.elf = elf


def _download_and_patch(ctx, info):
    if not info.libcfile and not info.ldfile:
        _make_template_exit()

    status, output = getstatusoutput("ldd " + info.elffile)
    lddoutput = output
    if status != 0:
        ctx.verrlog("ldd error!")
        _make_template_exit()

    if "/lib/x86_64-linux-gnu" in output:
        if info.libcfile:
            if info.glibcinfo:
                if info.sys_glibcinfo == info.glibcinfo:
                    _make_template_exit()
                else:
                    info.patchelf = 1
                    info.download = 1
            else:
                if info.ldfile:
                    info.patchelf = 1
                    info.download = 0
                else:
                    _make_template_exit()
        else:
            _make_template_exit()

    else:
        if info.libcfile:
            if info.glibcinfo:
                if info.ldfile:
                    info.download = 0
                else:
                    info.download = 1
                info.patchelf = 1
        else:
            ctx.verrlog("No libc in current directory!")
            _make_template_exit()

    if info.download and info.sys_glibcinfo and info.glibcinfo and info.sys_glibcinfo == info.glibcinfo:
        if not info.ldfile and info.sys_ldfile:
            getstatusoutput("cp -L {} .".format(info.sys_ldfile))
            info.ldfile = os.path.split(info.sys_ldfile)[1]
            info.download = 0

    if info.download:
        # TODO
        # unstrip first, then download deb
        # download ld first
        # unstrip
        # download dbg-deb

        pass

    if info.patchelf and info.libcfile and info.ldfile:
        curlibc = "./" + info.libcfile
        curld = "./" + info.ldfile
        curfile = "./" + info.elffile
        if curlibc not in lddoutput or curld not in lddoutput:
            # backup
            cmd = "cp {} {}.bk".format(curfile, curfile)
            getstatusoutput(cmd)
            cmd = "patchelf --replace-needed libc.so.6 {} {}".format(
                curlibc, curfile)
            getstatusoutput(cmd)
            ctx.vlog(_left_str("Exec cmd") + " --->    {}".format(cmd))

            cmd = "patchelf --set-interpreter {} {}".format(curld, curfile)
            getstatusoutput(cmd)
            ctx.vlog(_left_str("Exec cmd") + " --->    {}".format(cmd))

    pass


@click.command(name='initial', short_help="pwn initial tool, inspired by https://github.com/io12/pwninit.")
@pass_environ
def cli(ctx):
    ctx.verbose = 2
    info = _Inner_Dict()
    _collect_info(ctx, info)
    _detect_file(ctx, info)
    _download_and_patch(ctx, info)
    #print(repr(info))
    _make_template_exit()
