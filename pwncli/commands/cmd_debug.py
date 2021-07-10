import click
import subprocess
from pwn import context
import os
from pwncli.cli import pass_environ, gift, CONTEXT_SETTINGS, _treasure, _set_filename


def _check_set_value(ctx, filename, tmux, wsl, attach_mode, qemu_gdbport, gdb_breakpoint, gdb_script):
    global gift, _treasure
    if getattr(ctx, 'filename', 'error') != 'error':
        filename = None
    if tmux and wsl:
        wsl = False
    if (not tmux) and (not wsl):
        attach_mode = False
        gdb_breakpoint = []
        gdb_script = None
        qemu_gdbport = None

    if gdb_script:
        gdb_breakpoint = []

    _set_filename(ctx, filename, "debug-command set 'filename': {}".format(filename))





@click.command(name='debug', short_help="Debug the pwn file locally.", context_settings=CONTEXT_SETTINGS)
@click.option('-v', '--verbose', is_flag=True, help="Show more info or not.")
@click.option('-f', '--filename', type=str, default=None, help="Elf file path to pwn.")
@click.option('-t', '--tmux', is_flag=True, help="Use tmux to gdb-debug or not.")
@click.option('-w', '--wsl', is_flag=True, help="Use ubuntu.exe to gdb-debug or not.")
@click.option('-a', '--attach-mode', type=click.Choice(['auto', 'default', 'wsl-b', 'wsl-u', 'wsl-o']), nargs=1, default='auto', help="Gdb attach mode.")
@click.option('-qp', '--qemu-gdbport', type=int, nargs=1234, help="Only used for qemu, whose default gdb port is 1234. Only tmux supported.")
@click.option('-gb', '--gdb-breakpoint', default=[], type=str, multiple=True, help="Set gdb breakpoints while gdb is used, it should be a hex address or '\$rebase' addr or a function name. Multiple breakpoints are supported. Default value:'[]'")
@click.option('-gs', '--gdb-script', default=None, type=str, help="Set gdb commands like '-ex' or '-x' while gdb is used, the content will be passed to gdb and use ';' to split lines. Besides eval-commands, file path is supported. Default value:None")
@pass_environ
def cli(ctx,  verbose, filename, tmux, wsl, attach_mode, qemu_gdbport, gdb_breakpoint, gdb_script):
    ctx.verbose = verbose
    if verbose:
        ctx.vlog("debug-command open verbose mode")
    ctx.vlog("debug-command get 'filename': {}".format(filename))
    ctx.vlog("debug-command get 'tmux': {}".format(tmux))
    ctx.vlog("debug-command get 'wsl': {}".format(wsl))
    ctx.vlog("debug-command get 'attach_mode': {}".format(attach_mode))
    ctx.vlog("debug-command get 'qemu_gdbport': {}".format(qemu_gdbport))
    ctx.vlog("debug-command get 'gdb_breakpoint': {}".format(gdb_breakpoint))
    ctx.vlog("debug-command get 'gdb_script': {}".format(gdb_script))
    print('debug...')
    pass


# cli()