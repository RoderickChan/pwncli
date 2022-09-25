#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : cmd_debug.py
@Time    : 2021/11/23 23:49:55
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : debug subcommand
'''


import threading
import click
from pwn import context, which, ELF, pause
from pwnlib.atexit import register
from pwnlib.gdb import attach
import os
import re
import string
import tempfile
from pwncli.utils.config import try_get_config_data_by_key
from pwncli.cli import pass_environ, _set_filename
from pwncli.utils.misc import ldd_get_libc_path, _in_tmux, _in_wsl, _get_gdb_plugin_info
from pwncli.utils.cli_misc import CurrentGadgets

_NO_TERMINAL = 0
_USE_TMUX = 1
_USE_OTHER_TERMINALS = 2
_USE_GNOME_TERMINAL = 4


def __recover(f, c):
    # print("call recover")
    with open(f, "wb") as f2:
        f2.write(c)


def _set_gdb_type(pwncli_path, gdb_type):
    if gdb_type == 'auto':
        return None
    dirname = os.path.join(pwncli_path, "conf")

    if gdb_type == "pwndbg":
        gdbfile = ".gdbinit-pwndbg"
    elif gdb_type == "gef":
        gdbfile = ".gdbinit-gef"
    else:
        gdbfile = ".gdbinit-peda"

    fullpath = os.path.join(dirname, gdbfile)
    targpath = os.path.expanduser("~/.gdbinit")
    oldcontent = b""
    with open(targpath, "rb") as f:
        oldcontent = f.read()
    with open(targpath, "wb") as f:
        with open(fullpath, "rb") as f2:
            f.write(f2.read())
    return oldcontent, targpath


def _parse_env(ctx, env: str):
    length = len(env)
    # little check
    if (("=" not in env) and (':' not in env)) or (length < 3):
        ctx.abort(msg="debug-command --> Env is invalid, check your env input.")
    
    # use two points
    res=  {}
    first, second = 0, 1
    key, val = None, None
    while second < length:
        if env[second] in ('=', ':'):
            key = env[first: second].strip().upper() # 大写
            first = second + 1
            second += 2
        elif env[second] in (',', ';') or (key and second == length - 1):
            if second == length - 1 and (env[second] not in (';', ',')):
                second += 1
            # print(f"first: {first}, second: {second}")
            var = env[first: second].strip()
            if key == "PRE":
                key = "LD_PRELOAD"
            res[key] = var
            key, var = None, None
            first = second + 1
            second += 2
        else:
            second += 1

    if res:
        ctx.vlog('debug-command --> Set env: {}'.format(res))
    else:
        ctx.vlog2("debug-command --> No valid env exists.")
    return res

    


def _set_terminal(ctx, p, flag, attach_mode, use_gdb, gdb_type, script, is_file, gdb_script):
    terminal = None
    dirname = os.path.dirname(ctx.gift['filename'])
    
    if flag & _USE_TMUX: # use tmux
        terminal = ['tmux', 'splitw', '-h']
    elif flag & _USE_GNOME_TERMINAL:
        terminal = ["gnome-terminal", "--", "sh", "-c"]
    elif (flag & _USE_OTHER_TERMINALS) and which('cmd.exe'): # use cmd.exe to launch wt.exe bash.exe ...
        if is_file:
            gdbcmd = " {}\"".format("-x " + gdb_script)
        else:
            ex_script = ''
            for line in script.rstrip("\nc\n").split('\n'):
                if line:
                    ex_script += "-ex '{}' ".format(line)

            gdbcmd = " {}\"".format(ex_script)
        cmd = "cmd.exe /c start {} -c " + "\"cd {} && gdb -q attach {}".format(dirname, p.proc.pid) + gdbcmd

        if attach_mode == 'wsl-b' and which('bash.exe'):
            ctx.vlog2("debug-command --> Tips: Something error will happen if bash.exe not represent the default distribution.")
            cmd_use = cmd.format('bash.exe')
            ctx.vlog('debug-command --> Exec os.system({})'.format(cmd_use))
            os.system(cmd_use)
            return
        elif attach_mode == "wsl-w":
            distro_name = os.getenv("WSL_DISTRO_NAME")
            cmd_use = cmd.format("wsl.exe -d {} bash".format(distro_name))
            ctx.vlog('debug-command --> Exec os.system({})'.format(cmd_use))
            os.system(cmd_use)
            return
        else:
            distro_name = os.getenv('WSL_DISTRO_NAME')
            if not distro_name:
                ctx.abort('debug-command --> Cannot get distro name in wsl, please check your env!')
            
            if not re.search("ubuntu-\d\d.\d\d", distro_name, re.I):
                ctx.abort('debug-command --> Only support Ubuntu-XX.XX system!')
            
            ctx.vlog2("debug-command --> Find wsl distro, name '{}'".format(distro_name))
            ubuntu_exe_name = distro_name.lower().replace("-", "").replace(".", "") + ".exe"
            
            if attach_mode == 'wsl-u' and which(ubuntu_exe_name):
                cmd_use = cmd.format(ubuntu_exe_name)
                ctx.vlog('debug-command --> Exec os.system({})'.format(cmd_use))
                os.system(cmd_use)
                return # return
            elif attach_mode == 'wsl-wts' and which("wt.exe"):
                cmd_use = cmd.replace("cmd.exe /c start", "cmd.exe /c").\
                    format("wt.exe -w 0 split-pane -v wsl.exe -d {} bash".format(distro_name))
                ctx.vlog('debug-command --> Exec os.system({})'.format(cmd_use))
                os.system(cmd_use)
                return # return
            
            elif attach_mode == 'wsl-o' and which('open-wsl.exe'):
                terminal = ['open-wsl.exe', '-b', '-d {}'.format(distro_name),'-c']
            elif attach_mode == 'wsl-wt' and which('wt.exe'):
                terminal = ['cmd.exe', '/c', 'start', 'wt.exe', '-d', '\\\\wsl$\\{}{}'.format(distro_name, dirname.replace('/', '\\')),
                            'wsl.exe', '-d', distro_name, 'bash', '-c']
            else:
                ctx.vlog2('debug-command --> Wsl mode cannot launch a window, check whether the .exe in PATH.')
    gdb_type_res = None
    try:
        if terminal:
            context.terminal = terminal
            ctx.vlog("debug-command --> Set terminal: '{}'".format(' '.join(terminal)))
            gdb_type_res = _set_gdb_type(ctx.pwncli_path, gdb_type)
            gdb_pid, gdb_obj = attach(target=p, gdbscript=script, api=True)
            ctx.gift['gdb_pid'] = gdb_pid
            ctx.gift['gdb_obj'] = gdb_obj
                
        else:
            if use_gdb:
                ctx.vlog2("debug-command --> No tmux, no wsl, but use the pwntools' default terminal to use gdb because of 'use-gdb' enabled.")
                gdb_pid, gdb_obj = attach(target=p, gdbscript=script, api=True)
                ctx.gift['gdb_pid'] = gdb_pid
                ctx.gift['gdb_obj'] = gdb_obj
            else:
                ctx.vlog2("debug-command --> Terminal not set, no tmux or wsl would be used.")
    except:
        ctx.verrlog("debug-command --> Catch gdb error.")
    finally:
        # recover gdbinit file
        if gdb_type_res:
            ctx.vlog("debug-command --> Recover gdbinit file.")
            __recover(gdb_type_res[1], gdb_type_res[0])


def _check_set_value(ctx, filename, argv, env, use_tmux, use_wsl, use_gnome, attach_mode, 
                use_gdb, gdb_type, gdb_breakpoint, gdb_script, pause_before_main, hook_file, hook_function):
    # set filename
    if not ctx.gift.get('filename', None):
        _set_filename(ctx, filename, msg="debug-command --> Set 'filename': {}".format(filename))
        
    # filename is required
    if not ctx.gift.get('filename', None):
        ctx.abort("debug-command --> No 'filename'!")
    filename = ctx.gift['filename']
    context.binary = filename
    ctx.gift['elf'] = ELF(filename, checksec=False)

    # set argv
    if argv is not None:
        argv = argv.strip().split()
    else:
        argv = []
    
    # detect attach_mode
    __attachmode_mapping = {
        "t": "tmux",
        "a": "auto",
        "b": "wsl-b",
        "u": "wsl-u",
        "wt": "wsl-wt",
        "wts": "wsl-wts",
        "w": "wsl-w",
        "o": "wsl-o",
    }
    for _k, _v in __attachmode_mapping.items():
        if attach_mode == _k:
            attach_mode = _v
    
    if attach_mode.startswith('wsl'):
        use_wsl = True

    # check
    t_flag = _NO_TERMINAL
    # check tmux
    if use_tmux:
        if not _in_tmux():
            ctx.abort(msg="debug-command 'tmux' --> Not in tmux, please launch tmux first!")
        t_flag = _USE_TMUX
    # check wsl
    elif use_wsl:
        if not  _in_wsl():
            ctx.abort(msg="debug-command 'wsl' --> Not in wsl, the option -w is only used for wsl!")
        t_flag = _USE_OTHER_TERMINALS
    elif use_gnome:
        if not which("gnome-terminal"):
            ctx.abort(msg="debug-command 'gnome' --> No gnome-terminal, please install gnome-terminal first!")
        t_flag = _USE_GNOME_TERMINAL

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
            if gb.startswith('0x') or gb.isdecimal() or all(c in string.hexdigits for c in gb):
                script += 'b *{}\n'.format(gb)
            elif gb.startswith(('$rebase(', '$_base(')):
                fi = gb.index('(')
                bi = gb.index(')')
                script += "b *###({})\n".format(gb[fi+1: bi])
            elif gb.startswith('base+'):
                script += "b *###({})\n".format(gb[5:])
            elif gb.startswith('b+'):
                script += "b *###({})\n".format(gb[2:])
            else:
                script += 'b {}\n'.format(gb)
    script += 'c\n'
    gdb_type_change_flag = 0
    if gdb_type == "auto":
        gdb_type = _get_gdb_plugin_info()
        gdb_type_change_flag = 1
    
    if gdb_type == 'pwndbg':
        script = script.replace("###", "$rebase")
    elif gdb_type == "gef":
        script = script.replace("###(", "($_base()+")
    else:
        if "###" in script:
            ctx.abort(msg="debug-command 'gdb breakpoint' --> Cannot set base bp in peda or original gdb.")

    if gdb_type_change_flag:
        gdb_type = 'auto'

    # if gdb_script is file, then open it
    if is_file:
        if script:
            tmp_fd, tmp_gdb_script = tempfile.mkstemp(text=True)
            ctx.vlog("debug-command --> Create a tempfile used for gdb_script, file path: {}".format(tmp_gdb_script))
            os.close(tmp_fd)
            register(lambda x: os.unlink(x), tmp_gdb_script)
            with open(tmp_gdb_script, 'wt', encoding='utf-8') as f:
                f.write(script +"\n")
                with open(gdb_script, "rt", encoding='utf-8') as f2:
                    f.write(f2.read() + "\n")
            gdb_script = tmp_gdb_script
        script = open(gdb_script, "r", encoding="utf-8")
    
    if env:
        env = _parse_env(ctx, env)
        if not env:
            env = None

    if pause_before_main or hook_file or len(hook_function) > 0:
        if which("gcc"):
            file_content = ""
            if hook_file and os.path.exists(hook_file):
                with open(hook_file, "r", encoding="utf-8") as hook_f:
                    file_content += hook_f.read()
            if pause_before_main:
                file_content = "#include <stdio.h>\n" + file_content
                file_content +="""
void pause_before_main(void) __attribute__((constructor));

void pause_before_main()
{{
    getchar();
}}
                """
            for __func in hook_function:
                print(__func)
                file_content += """
int {}()
{{
    return 0;
}}
                """.format(__func)
            _, tmp_path = tempfile.mkstemp(suffix=".c", text=True)
            with open(tmp_path, "w", encoding="utf-8") as tem_f:
                tem_f.write(file_content)
            cmd = "gcc -g -fPIC -shared {} -o {}.so".format(tmp_path, tmp_path)
            if context.bits == 32:
                cmd += " -m32"
            ctx.vlog("debug-command 'pause_before_main/hook_file' --> Execute cmd '{}'.".format(cmd))
            register(lambda x: os.unlink(x) or os.unlink("{}.so".format(x)), tmp_path)
            if not os.system(cmd):
                ctx.vlog(msg="debug-command 'pause_before_main/hook_file' --> Execute last cmd success.")
                if env:
                    env['LD_PRELOAD'] += ":{}.so".format(tmp_path)
                else:
                    env = {'LD_PRELOAD': "{}.so".format(tmp_path)}
            else:
                ctx.verrlog(msg="debug-command 'pause_before_main/hook_file' --> Execute last cmd failed.")
        else:
            ctx.verrlog(msg="debug-command 'pause_before_main' --> Cannot find gcc in PATH.")

    # set binary
    
    ctx.gift['io'] = context.binary.process(argv, timeout=ctx.gift['context_timeout'], env=env)
    ctx.vlog('debug-command --> Set process({}, argv={}, env={})'.format(filename, argv, env))
    
    rp = None
    if env and "LD_PRELOAD" in env:
        for rp_ in env["LD_PRELOAD"].split(";"):
            if "libc" in rp_:
                rp = rp_
                break

    if not rp:
        rp = ldd_get_libc_path(filename)

    if rp:
        ctx.gift['libc'] = ELF(rp, checksec=False)
        ctx.gift['libc'].address = 0
    else:
        ctx.vlog2('debug-command --> ldd cannot find the libc.so.6 or libc-2.xx.so, and rename your libc file to "libc.so.6" if you add it to LD_PRELOAD')
    
    # set gdb-type
    if t_flag == _NO_TERMINAL and gdb_type != "auto":
        if _in_tmux():
            t_flag = _USE_TMUX
        elif _in_wsl():
            t_flag = _USE_OTHER_TERMINALS
        else:
            use_gdb = True
            ctx.vlog2("debug-command --> set 'gdb_type' but not in tmux or in wsl, so set 'use_gdb' True.")
    
    # set attach-mode 'auto'
    if attach_mode == 'auto':
        if t_flag == _USE_TMUX or (_in_tmux() and t_flag != _USE_OTHER_TERMINALS):
            attach_mode = 'tmux'
        elif which("wt.exe"):
            attach_mode = 'wsl-wt'
        elif which("wsl.exe"):
            attach_mode = "wsl-w"
        elif which('open-wsl.exe'):
            attach_mode = 'wsl-o'
        elif which('bash.exe') is None:
            attach_mode = 'wsl-u'
        else:
            attach_mode = 'wsl-b' # don't know whether bash.exe is correct 
    
    # set terminal
    _set_terminal(ctx, ctx.gift['io'], t_flag, attach_mode, use_gdb, gdb_type, script, is_file, gdb_script)

    if pause_before_main:
        pause() # avoid read from stdin
        ctx.gift.io.send("X")

    # from cli, keep interactive
    if ctx.fromcli: 
        ctx.gift['io'].interactive()
    else:
        res = try_get_config_data_by_key(ctx.config_data, "debug", "load_gadget")
        if res and res.strip().lower() in ("true", "yes", "enabled", "enable", "1"):
            threading.Thread(target=lambda :CurrentGadgets.reset(), daemon=True).start()



@click.command(name='debug', short_help="Debug the pwn file locally.")
@click.argument('filename', type=str, default=None, required=False, nargs=1)
@click.option('--argv', type=str, default=None, required=False, show_default=True, help="Argv for process.")
@click.option("-e", '--set-env', "--env", "env", type=str, default=None, required=False, help="The env setting for process, such as LD_PRELOAD setting, split using ',' or ';', assign using '=' or ':'.")
@click.option('-p', '--pause', '--pause-before-main', "pause_before_main", is_flag=True, show_default=True, help="Pause before main is called or not, which is helpful for gdb attach.")
@click.option('-f', '-hf','--hook-file', "hook_file", type=str,  default=None, required=False, help="Specify a hook.c file, where you write some functions to hook.")
@click.option('-H', '-HF', '--hook-function', "hook_function", default=[], type=str, multiple=True, show_default=True, help="The functions you want to hook would be out of work.")
@click.option('-t', '--use-tmux', '--tmux', "tmux", is_flag=True, show_default=True, help="Use tmux to gdb-debug or not.")
@click.option('-w', '--use-wsl', '--wsl', "wsl", is_flag=True, show_default=True, help="Use wsl to pop up windows for gdb-debug or not.")
@click.option('-g', '--use-gnome', '--gnome', "gnome", is_flag=True, show_default=True, help="Use gnome terminal to pop up windows for gdb-debug or not.")
@click.option('-m', '-am', '--attach-mode', "attach_mode", type=click.Choice(['auto', 'tmux', 'wsl-b', 'wsl-u', 'wsl-o', 'wsl-wt', 'wsl-wts', 'wsl-w', 'a', 't', 'w', 'wt', 'wts', 'b', 'o', 'u']), nargs=1, default='auto', show_default=True, help="Gdb attach mode, wsl: bash.exe | wsl: ubuntu1x04.exe | wsl: open-wsl.exe | wsl: wt.exe wsl.exe")
@click.option('-u', '-ug', '--use-gdb', "use_gdb", is_flag=True, show_default=True, help="Use gdb possibly.")
@click.option('-G', '-gt','--gdb-type', "gdb_type", type=click.Choice(['auto', 'pwndbg', 'gef', 'peda']), nargs=1, default='auto', help="Select a gdb plugin.")
@click.option('-b', '-gb', '--gdb-breakpoint', "gdb_breakpoint", default=[], type=str, multiple=True, show_default=True, help="Set gdb breakpoints while gdb-debug is used, it should be a hex address or '\$rebase' addr or a function name. Multiple breakpoints are supported.")
@click.option('-s', '-gs', '--gdb-script', "gdb_script", default=None, type=str, show_default=True, help="Set gdb commands like '-ex' or '-x' while gdb-debug is used, the content will be passed to gdb and use ';' to split lines. Besides eval-commands, file path is supported.")
@click.option('-n', '-nl', '--no-log', "no_log", is_flag=True, show_default=True, help="Disable context.log or not.")
@click.option('-P', '-ns', '--no-stop', "no_stop", is_flag=True, show_default=True, help="Use the 'stop' function or not. Only for python script mode.")
@click.option('-v', '--verbose', count=True, help="Show more info or not.")
@pass_environ
def cli(ctx, verbose, filename, argv, env, 
        tmux, wsl, gnome, attach_mode, use_gdb, gdb_type, gdb_breakpoint, gdb_script, 
        no_log, no_stop, pause_before_main, hook_file, hook_function):
    """FILENAME: The ELF filename.

    \b
    Debug in tmux:
        python3 exp.py debug ./pwn --tmux --gdb-breakpoint malloc -gb 0x400789
    """
    ctx.vlog("Welcome to use pwncli-debug command~")
    if not ctx.verbose:
        ctx.verbose = verbose
    if verbose:
        ctx.vlog("debug-command --> Open 'verbose' mode")

    # log verbose info
    ctx.vlog("debug-command --> Get 'filename': {}".format(filename))
    ctx.vlog("debug-command --> Get 'argv': {}".format(argv))
    ctx.vlog("debug-command --> Get 'env': {}".format(env))
    ctx.vlog("debug-command --> Get 'pause_before_main': {}".format(pause_before_main))
    ctx.vlog("debug-command --> Get 'hook_file': {}".format(hook_file))
    ctx.vlog("debug-command --> Get 'hook_function': {}".format(hook_function))
    ctx.vlog("debug-command --> Get 'no-log': {}".format(no_log))
    ctx.vlog("debug-command --> Get 'no-stop': {}".format(no_stop))
    ctx.vlog("debug-command --> Get 'tmux': {}".format(tmux))
    ctx.vlog("debug-command --> Get 'wsl': {}".format(wsl))
    ctx.vlog("debug-command --> Get 'gnome': {}".format(gnome))
    ctx.vlog("debug-command --> Get 'attach_mode': {}".format(attach_mode))
    ctx.vlog("debug-command --> Get 'use_gdb': {}".format(use_gdb))
    ctx.vlog("debug-command --> Get 'gdb_type': {}".format(gdb_type))
    ctx.vlog("debug-command --> Get 'gdb_breakpoint': {}".format(gdb_breakpoint))
    ctx.vlog("debug-command --> Get 'gdb_script': {}".format(gdb_script))

    ctx.gift['debug'] = True
    ctx.gift['no_stop'] = no_stop

    ll = 'error' if no_log else ctx.gift['context_log_level']
    context.update(log_level=ll)
    ctx.vlog("debug-command --> Set 'context.log_level': {}".format(ll))

    # set value
    _check_set_value(ctx, filename, argv, env, tmux, wsl, gnome, attach_mode, 
                use_gdb, gdb_type, gdb_breakpoint, gdb_script, pause_before_main, hook_file, hook_function)


    
