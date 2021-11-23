#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : cmd_debug.py
@Time    : 2021/11/23 23:49:55
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : debug subcommand
'''


import click
import subprocess
from pwn import context, process, which, ELF, sleep
from pwnlib.gdb import attach
import os
import sys
from pwncli.cli import pass_environ, _set_filename
from pwncli.utils.config import try_get_config_data_by_key
from pwncli.utils.misc import ldd_get_libc_path


def _set_terminal(ctx, p, flag, attach_mode, script, is_file, gdb_script):
    terminal = None
    dirname = os.path.dirname(os.path.abspath(ctx.gift['filename']))

    if flag & 1: # use tmux
        terminal = ['tmux', 'splitw', '-h']
    elif (flag & 2) and which('cmd.exe'): # use cmd.exe to launch wt.exe bash.ex ...
        if is_file:
            gdbcmd = " {}\"".format("-x " + gdb_script)
        else:
            ex_script = ''
            for line in script.rstrip("\nc\n").split('\n'):
                if line is None or line == '':
                    continue
                ex_script += "-ex '{}' ".format(line)

            gdbcmd = " {}\"".format(ex_script)
        cmd = "cmd.exe /c start {} -c " + "\"cd {};gdb -q attach {}".format(dirname, p.proc.pid) + gdbcmd

        if attach_mode == 'wsl-b' and which('bash.exe'):
            ctx.vlog2("debug-command --> Tips: Something error will happen if bash.exe not represent the default distribution.")
            cmd_use = cmd.format('bash.exe')
            ctx.vlog('debug-command --> Exec os.system({})'.format(cmd_use))
            os.system(cmd_use)
            return
        else:
            ubu_name = ''
            with open('/etc/issue', mode='rb') as f:
                content = f.read()
            if b'16.04' in content:
                ubu_name = '16.04'
            elif b'18.04' in content:
                ubu_name = '18.04'
            elif b'20.04' in content:
                ubu_name = '20.04'
            else:
                ctx.abort('debug-command --> Only support ubuntu 16.04/18.04/20.04 in wsl')

            distro_name = 'Ubuntu-{}'.format(ubu_name)
            ubuntu_exe_name = 'ubuntu{}.exe'.format(ubu_name.replace('.', ""))
            ctx.vlog2("debug-command --> Try to find wsl distro, name '{}'".format(distro_name))

            if attach_mode == 'wsl-u' and which(ubuntu_exe_name):
                cmd_use = cmd.format(ubuntu_exe_name)
                ctx.vlog('debug-command --> Exec os.system({})'.format(cmd_use))
                os.system(cmd_use)
                return # return
            elif attach_mode == 'wsl-o' and which('open-wsl.exe'):
                terminal = ['open-wsl.exe', '-b', '-d {}'.format(distro_name),'-c']
            elif attach_mode == 'wsl-wt' and which('wt.exe'):
                terminal = ['cmd.exe', '/c', 'start', 'wt.exe', '-d', '\\\\wsl$\\{}{}'.format(distro_name, dirname.replace('/', '\\')),
                            'wsl.exe', '-d', distro_name, 'bash', '-c']

    if terminal:
        context.terminal = terminal
        ctx.vlog("debug-command --> Set terminal: '{}'".format(' '.join(terminal)))
        gdb_pid, gdb_obj = attach(target=p, gdbscript=script, api=True)
        ctx.gift['gdb_pid'] = gdb_pid
        ctx.gift['gdb_obj'] = gdb_obj
            
    else:
        if ctx.use_gdb:
            ctx.vlog2("debug-command --> No tmux, no wsl, but use the pwntools' default terminal to use gdb because of 'use-gdb' enabled.")
            gdb_pid, gdb_obj = attach(target=p, gdbscript=script, api=True)
            ctx.gift['gdb_pid'] = gdb_pid
            ctx.gift['gdb_obj'] = gdb_obj
            return
        ctx.vlog2("debug-command --> Terminal not set, no tmux, no wsl")


def _check_set_value(ctx, filename, argv, tmux, wsl, attach_mode, qemu_gdbremote, gdb_breakpoint, gdb_script):
    # set filename
    if not ctx.gift.get('filename', None):
        _set_filename(ctx, filename, msg="debug-command --> Set 'filename': {}".format(filename))
    
    # set argv
    if argv is not None:
        argv = argv.strip().split()
    else:
        argv = []
    
    # detect attach_mode
    if attach_mode.startswith('wsl'):
        wsl = True

    # check
    t_flag = 0
    # check tmux
    if tmux and (not bool('TMUX' in os.environ and which('tmux'))):
        ctx.abort(msg="debug-command 'tmux' --> Not in tmux")
    if tmux:
        t_flag = 1
        wsl = None
    # check wsl
    if wsl:
        is_wsl = False
        if os.path.exists('/proc/sys/kernel/osrelease'):
            with open('/proc/sys/kernel/osrelease', 'rb') as f:
                is_wsl = b'icrosoft' in f.read()
        if (not is_wsl) or (not which('wsl.exe')):
            ctx.abort(msg="debug-command 'wsl' --> Not in wsl")
        t_flag = 2

    # process gdb-scripts
    is_file = False
    script = ''
    if gdb_script:
        if os.path.isfile(gdb_script):
            is_file = True
        else:
            script = gdb_script.strip().replace(';', '\n') + '\n'
    if gdb_breakpoint and len(gdb_breakpoint) > 0:
        for gb in gdb_breakpoint:
            if gb.startswith('0x') or gb.startswith('$rebase('):
                script += 'b *{}\n'.format(gb)
            else:
                script += 'b {}\n'.format(gb)
    script += 'c\n'

    # process special condition ---> qemu-gdbremote
    if qemu_gdbremote:
        if not bool('TMUX' in os.environ and which('tmux')):
            ctx.abort("debug-command 'qemu_gdbremote' -->  Not in tmux")
        if ':' in qemu_gdbremote:
            ip, port = qemu_gdbremote.strip().split(';')
            port = int(port)
        else:
            ip = 'localhost'
            port = int(qemu_gdbremote)
        tmux_path = which('tmux')
        gdb_path = which('gdb')
        gdbx = '{} -q -ex "target remote {}:{}"'.format(gdb_path, ip, port)
        if is_file:
            gdbx += ' -x {}'.format(gdb_script)

        os.system(' '.join([tmux_path, 'splitw', '-h', gdbx]))
        return

    # if gdb_script is file, then open it
    if is_file:
        script = open(gdb_script, 'r', encoding='utf-8')

    # check filename now
    if not ctx.gift.get('filename', None):
        ctx.abort("debug-command --> No 'filename'!")
    filename = ctx.gift['filename']
    # set binary
    context.binary = filename
    ctx.gift['io'] = context.binary.process(argv, timeout=ctx.gift['context_timeout'])
    ctx.gift['elf'] = ELF(filename, checksec=False)

    rp = ldd_get_libc_path(filename)
    if rp is not None:
        ctx.gift['libc'] = ELF(rp, checksec=False)
        ctx.gift['libc'].address = 0
    else:
        ctx.vlog2('debug-command --> ldd cannot find the libc.so.6 or libc-2.xx.so')
    ctx.vlog('debug-command --> Set process({}, argv={})'.format(filename, argv))

    # set attach-mode 'auto'
    if attach_mode == 'auto':
        if tmux or (('TMUX' in os.environ and which('tmux')) and (not wsl)):
            attach_mode = 'tmux'
        elif which("wt.exe"):
            attach_mode = 'wsl-wt'
        elif which('open-wsl.exe'):
            attach_mode = 'wsl-o'
        elif which('bash.exe') is None:
            attach_mode = 'wsl-u'
        else:
            attach_mode = 'wsl-b' # don't know whether bash.exe is correct 

    # set terminal
    _set_terminal(ctx, ctx.gift['io'], t_flag, attach_mode, script, is_file, gdb_script)

    # from cli, keep interactive
    if ctx.fromcli: 
        ctx.gift['io'].interactive()


@click.command(name='debug', short_help="Debug the pwn file locally.")
@click.argument('filename', type=str, default=None, required=False, nargs=1)
@click.option('--argv', type=str, default=None, required=False, show_default=True, help="Argv for process.")
@click.option('-v', '--verbose', count=True, help="Show more info or not.")
@click.option('-nl', '--no-log', is_flag=True, show_default=True, help="Disable context.log or not.")
@click.option('-t', '--tmux', is_flag=True, show_default=True, help="Use tmux to gdb-debug or not.")
@click.option('-w', '--wsl', is_flag=True, show_default=True, help="Use wsl to pop up windows for gdb-debug or not.")
@click.option('-m', '--attach-mode', type=click.Choice(['auto', 'tmux', 'wsl-b', 'wsl-u', 'wsl-o', 'wsl-wt']), nargs=1, default='auto', show_default=True, help="Gdb attach mode, wsl: bash.exe | wsl: ubuntu1234.exe | wsl: open-wsl.exe | wsl: wt.exe wsl.exe")
@click.option('-qg', '--qemu-gdbremote', type=str, default=None, show_default=True, help="Only used for qemu, who opens the gdb listening port. Only tmux supported.Format: ip:port or only port for localhost.")
@click.option('-gb', '--gdb-breakpoint', default=[], type=str, multiple=True, show_default=True, help="Set gdb breakpoints while gdb-debug is used, it should be a hex address or '\$rebase' addr or a function name. Multiple breakpoints are supported.")
@click.option('-gs', '--gdb-script', default=None, type=str, show_default=True, help="Set gdb commands like '-ex' or '-x' while gdb-debug is used, the content will be passed to gdb and use ';' to split lines. Besides eval-commands, file path is supported.")
@pass_environ
def cli(ctx, verbose, filename, argv, tmux, wsl, attach_mode, qemu_gdbremote, gdb_breakpoint, gdb_script, no_log):
    """FILENAME: The ELF filename.

    \b
    Debug in tmux:
        python3 exp.py debug ./pwn -t -gb malloc -gb 0x400789
    """
    ctx.vlog("Welcome to use pwncli-debug command~")
    if not ctx.verbose:
        ctx.verbose = verbose
    if verbose:
        ctx.vlog("debug-command --> Open 'verbose' mode")

    # log verbose info
    ctx.vlog("debug-command --> Get 'filename': {}".format(filename))
    ctx.vlog("debug-command --> Get 'argv': {}".format(argv))
    ctx.vlog("debug-command --> Get 'tmux': {}".format(tmux))
    ctx.vlog("debug-command --> Get 'wsl': {}".format(wsl))
    ctx.vlog("debug-command --> Get 'attach_mode': {}".format(attach_mode))
    ctx.vlog("debug-command --> Get 'qemu_gdbport': {}".format(qemu_gdbremote))
    ctx.vlog("debug-command --> Get 'gdb_breakpoint': {}".format(gdb_breakpoint))
    ctx.vlog("debug-command --> Get 'gdb_script': {}".format(gdb_script))

    ctx.gift['debug'] = True

    ll = 'error' if no_log else ctx.gift['context_log_level']
    context.update(log_level=ll)
    ctx.vlog("debug-command --> Set 'context.log_level': {}".format(ll))

    # set value
    _check_set_value(ctx, filename, argv, tmux, wsl, attach_mode, qemu_gdbremote, gdb_breakpoint, gdb_script)


    
