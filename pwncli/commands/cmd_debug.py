import click
import subprocess
from pwn import context, process, which
from pwnlib.gdb import attach
import os
from pwncli.cli import pass_environ, gift, CONTEXT_SETTINGS, _treasure, _set_filename


def _set_terminal(ctx, p, flag, attach_mode, script:str, is_file, gdb_script):
    terminal = None
    dirname = os.path.dirname(os.path.abspath(ctx.filename))
    if flag & 1:
        terminal = ['tmux', 'splitw', '-h']
    elif which('cmd.exe'):
        if is_file:
            subcmd = " {}\"".format("-x " + gdb_script)
        else:
            ex_script = ''
            for line in script.rstrip("\nc\n").split('\n'):
                ex_script += '-ex "{}" '.format(line)

            subcmd = " {}\"".format(ex_script)
        cmd = "cmd.exe /c start {} -c " + "\"cd {};gdb -q attach {}".format(dirname, p.proc.pid) + subcmd

        if attach_mode == 'wsl-b' and which('bash.exe'):
            # terminal = ['cmd.exe', '/c','start','bash.exe', '-c']
            ctx.vlog("debug-command Tips: Something error will happen if bash.exe not represent the default distribution.")
            cmd_use = cmd.format('bash.exe')
            ctx.vlog('debug-command exec os.system({})'.format(cmd_use))
            os.system(cmd_use)
            return
        else:
            ubu_name = ''
            with open('/etc/issue', mode='rb') as f:
                content = f.read()
            if b'16.04' in content:
                ubu_name = '1604'
            elif b'18.04' in content:
                ubu_name = '1804'
            elif b'20.04' in content:
                ubu_name = '2004'
            else:
                ctx.abort('debug-command: Only support ubuntu 16.04/18.04/20.04 in wsl')

            use_name = 'Ubuntu-{}'.format(ubu_name)

            if attach_mode == 'wsl-u' and which('ubuntu'+ubu_name+'.exe'):
                # terminal = ['cmd.exe', '/c','start', 'ubuntu'+ubu_name+'.exe', '-c'] # home directory
                cmd_use = cmd.format('ubuntu' + ubu_name + '.exe')
                ctx.vlog('debug-command exec os.system({})'.format(cmd_use))
                os.system(cmd_use)
                return # return
            elif attach_mode == 'wsl-o' and which('open-wsl.exe'):
                terminal = ['cmd.exe', '/c', 'start', 'open-wsl.exe', '-b', '-d {}'.format(use_name), '-c']
            elif attach_mode == 'wsl-wt' and which('wt.exe'):
                terminal = ['cmd.exe', '/c', 'start', 'wt.exe', '-d', '\\\\wsl$\\{}{}'.format(use_name, dirname.replace('/', '\\')),
                            'wsl.exe', '-d', use_name, 'bash', '-c']
    if terminal:
        context.terminal = terminal
        ctx.vlog("debug-command set terminal: '{}'".format(', '.join(terminal)))
    attach(target=p, gdbscript=script)


def _check_set_value(ctx, filename, tmux, wsl, attach_mode, qemu_gdbremote, gdb_breakpoint, gdb_script):
    global gift, _treasure
    gift['debug'] = True
    if getattr(ctx, 'filename', 'error') != 'error':
        filename = None
    else:
        ctx.verrlog("debug-command: No 'filename'!")

    _set_filename(ctx, filename, msg="debug-command set 'filename': {}".format(filename))
    # check tmux
    if tmux and (not bool('TMUX' in os.environ and which('tmux'))):
        ctx.abort(msg="debug-command 'tmux': Not in tmux")
    if tmux:
        wsl = None
    # check wsl
    if wsl:
        is_wsl = False
        if os.path.exists('/proc/sys/kernel/osrelease'):
            with open('/proc/sys/kernel/osrelease', 'rb') as f:
                is_wsl = b'icrosoft' in f.read()
        if (not is_wsl) or (not which('wsl.exe')):
            ctx.abort(msg="debug-command 'wsl': Not in wsl")

    # process bps
    is_file = False
    script = ''
    if gdb_script:
        if os.path.isfile(gdb_script):
            is_file = True
        else:
            script = gdb_script.replace(';', '\n') + '\n'
    if (not gdb_breakpoint) and len(gdb_breakpoint) > 0:
        for gb in gdb_breakpoint:
            if gb.startswith('0x') or gb.startswith('$rebase('):
                script += 'b *{}\n'.format(gb)
            else:
                script += 'b {}\n'.format(gb)
    script += 'c\n'

    # process special condition
    if qemu_gdbremote:
        if not bool('TMUX' in os.environ and which('tmux')):
            ctx.abort("debug-command 'qemu_gdbremote': Not in tmux")
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

    if is_file:
        script = open(gdb_script, 'r', encoding='utf-8')

    p = process(ctx.filename)
    gift['io'] = p
    ctx.vlog('debug-command set process({})'.format(ctx.filename))

    if (not tmux) and (not wsl):
        ctx.vlog("debug-command set terminal: None")
        ctx.verrlog('debug-command: gdb is not opend due to no tmux and no wsl')
        return





@click.command(name='debug', short_help="Debug the pwn file locally.", context_settings=CONTEXT_SETTINGS)
@click.option('-v', '--verbose', is_flag=True, help="Show more info or not.")
@click.option('-f', '--filename', type=str, default=None, help="Elf file path to pwn.")
@click.option('-t', '--tmux', is_flag=True, help="Use tmux to gdb-debug or not.")
@click.option('-w', '--wsl', is_flag=True, help="Use ubuntu.exe to gdb-debug or not.")
@click.option('-a', '--attach-mode', type=click.Choice(['tmux', 'wsl-b', 'wsl-u', 'wsl-o', 'wsl-wt']), nargs=1, default='tmux', help="Gdb attach mode, wsl: bash.exe | wsl: ubuntu1234.exe | wsl: open-wsl.exe | wsl: wt.exe wsl.exe")
@click.option('-qp', '--qemu-gdbremote', type=str, default=None, help="Only used for qemu, who opens the gdb listening port. Only tmux supported.Format: ip:port or only port for localhost.")
@click.option('-gb', '--gdb-breakpoint', default=[], type=str, multiple=True, help="Set gdb breakpoints while gdb-debug is used, it should be a hex address or '\$rebase' addr or a function name. Multiple breakpoints are supported. Default value:'[]'")
@click.option('-gs', '--gdb-script', default=None, type=str, help="Set gdb commands like '-ex' or '-x' while gdb-debug is used, the content will be passed to gdb and use ';' to split lines. Besides eval-commands, file path is supported. Default value:None")
@pass_environ
def cli(ctx,  verbose, filename, tmux, wsl, attach_mode, qemu_gdbremote, gdb_breakpoint, gdb_script):
    if not ctx.verbose:
        ctx.verbose = verbose
    if verbose:
        ctx.vlog("debug-command open 'verbose' mode")

    ctx.vlog("debug-command get 'filename': {}".format(filename))
    ctx.vlog("debug-command get 'tmux': {}".format(tmux))
    ctx.vlog("debug-command get 'wsl': {}".format(wsl))
    ctx.vlog("debug-command get 'attach_mode': {}".format(attach_mode))
    ctx.vlog("debug-command get 'qemu_gdbport': {}".format(qemu_gdbremote))
    ctx.vlog("debug-command get 'gdb_breakpoint': {}".format(gdb_breakpoint))
    ctx.vlog("debug-command get 'gdb_script': {}".format(gdb_script))

    pass


# cli()