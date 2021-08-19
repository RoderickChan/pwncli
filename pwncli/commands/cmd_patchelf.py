import click
import sys
import os
from pwncli.cli import pass_environ
from pwn import which
from pwncli.utils.config import *


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


@click.command(name='patchelf', short_help="Patchelf command.")
@click.argument('filename', type=str, required=True, nargs=1)
@click.argument("libc-version", required=True, nargs=1, type=str)
@click.option('-b', '--back-up', is_flag=True, help="Backup target file or not.")
@pass_environ
def cli(ctx, filename, libc_version, back_up):
    """FILENAME: ELF executable filename.\n
    LIBC_VERSION: Libc version.

    \b
    pwncli patchelf ./filename 2.29
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
    
    subdirs = list(filter(lambda x: (archinfo in x) and (os.path.isdir(os.path.join(libc_dirname, x))), os.listdir(libc_dirname)))
    subdirs.sort()
    
    has_versions = [x[:4] for x in subdirs]
    
    if libc_version not in has_versions:
        ctx.verrlog("patchelf-command --> Do not have the libc version of {}, only have {}!".format(libc_version, has_versions))
        ctx.abort()

    # backup first
    if back_up:
        cmd = "cp {} {}".format(filename, filename+".bk")
        ctx.vlog("patchelf-command --> Backup file named: {}".format(filename+".bk"))
        os.system(cmd)
    
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
    