import click
import sys
import os
import subprocess
from pwn import which
from pwncli.cli import pass_environ


@click.command(name='qemu', short_help="Use qemu to debug pwn, for kernel pwn or arm/mips arch.")
@click.option('-v', '--verbose', count=True, show_default=True, help="Show more info or not.")
@pass_environ
def cli(ctx, verbose):
    ctx.vlog("Welcome to use pwncli-qemu command~")
    if not ctx.verbose:
        ctx.verbose = verbose
    if verbose:
        ctx.vlog("debug-qemu --> Open 'verbose' mode")
    raise NotImplementedError("TODO")