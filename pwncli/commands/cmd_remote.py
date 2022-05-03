#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : cmd_remote.py
@Time    : 2021/11/23 23:50:34
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : remote subcommand
'''


import threading
import click
import os
from collections import OrderedDict
from pwncli.cli import pass_environ, _set_filename
from pwn import remote, ELF,context
from pwncli.utils.cli_misc import CurrentGadgets
from pwncli.utils.config import *
from pwncli.utils.misc import ldd_get_libc_path


def do_setproxy(ctx, proxy_mode):
    if proxy_mode in ('notset', 'undefined'):
        return None

    if not ctx.config_data:
        ctx.verrlog("remote-command --> Set-proxy failed due to no config data!")
        return None

    data = ctx.config_data
    if not data.has_section('proxy'):
        ctx.verrlog("remote-command --> Config data has no section named 'proxy'!")
        return None
    
    proxy_setting = data['proxy']
    socks_type = {1:"socks4", 2:"socks5", 3:"http"}
    socks_type2 = dict(zip(socks_type.values(), socks_type.keys()))
    proxy_type = 2 # sockts5
    
    if 'type' in proxy_setting:
        proxy_type = proxy_setting['type'].lower()
        if proxy_type.isnumeric():
            proxy_type = int(proxy_type)
            if proxy_type not in socks_type:
                ctx.abort(msg="Wrong proxy_type! Valid value:{}".format(socks_type))
        else:
            if proxy_type not in socks_type2:
                ctx.abort(msg="Wrong proxy_type! Valid value:{}".format(socks_type))
            proxy_type = socks_type2[proxy_type]

    proxy_host = proxy_setting['host'] if 'host' in proxy_setting else "localhost"
    proxy_port = int(proxy_setting['port']) if 'port' in proxy_setting else 8080
    username = proxy_setting['username'] if 'username' in proxy_setting else None
    passwd = proxy_setting['passwd'] if 'passwd' in proxy_setting else None
    rdns = bool(proxy_setting['rdns']) if 'rdns' in proxy_setting else True
    proxy_descripe = ('proxy_type', 'proxy_host', "proxy_port", "rdns", "username", "passwd")
    proxy_data = (proxy_type, proxy_host, proxy_port, rdns, username, passwd)
    pstr=''
    for k, v in OrderedDict(zip(proxy_descripe, proxy_data[:-1] + ('******',))).items():
        # make proxy_type pretty
        if k == "proxy_type":
            v = socks_type[v]
        pstr += '{}: {}  '.format(k, v)
    ctx.vlog("remote-command --> Set 'proxy': {}".format(pstr))
    ctx.gift['proxy'] = proxy_data

    if proxy_mode == "default":
        context.proxy = proxy_data
        return None
    else:
        import socks
        import socket
        socks.set_default_proxy(*proxy_data)
        socket.socket = socks.socksocket
        s = socket.socket()
        return s


def do_remote(ctx, filename, target, ip, port, proxy_mode):
    # detect filename and target
    if filename and target:
        if os.path.exists(target):
            filename, target = target, filename
    elif filename or target:
        temp = filename or target
        if os.path.exists(temp):
            filename = temp
            target = None
        else:
            target = temp
            filename = None
    elif ip is None or port is None or len(ip) == 0 or port <= 0: # little check
            ctx.abort("remote-command --> Cannot get the victim host!")

    if not ctx.gift.get('filename', None):
        _set_filename(ctx, filename, msg="remote-command --> Set 'filename': {}".format(filename))
    filename = ctx.gift.get('filename', None)
    if filename:
        context.binary = filename
        ctx.gift['elf'] = ELF(filename, checksec=False)
        
        rp = ldd_get_libc_path(filename)
        if rp is not None:
            ctx.gift['libc'] = ELF(rp, checksec=False)
            ctx.gift['libc'].address = 0
        else:
            ctx.vlog2('remote-command --> ldd cannot find the libc.so.6 or libc-2.xx.so')
    else:
        ctx.vlog2("remote-command --> Filename is None, so maybe you need to set context manually.")
    
    if target:
        if ":" not in target: # little check
            ctx.abort("remote-command --> {} is a wrong 'target' format, should be 'ip:port'".format(target))
        ip, port = target.strip().split(':')
        ip = ip.strip()
        port = int(port)
        ctx.vlog("remote-command --> Get 'target': {}".format(target))
    elif ip and port:
        ctx.vlog("remote-command --> Get 'ip': {}".format(ip))
        ctx.vlog("remote-command --> Get 'port': {}".format(port))
    else:
        ctx.abort("remote-command --> Cannot get the victim host!")
    
    # set proxy
    s = do_setproxy(ctx, proxy_mode)
    ctx.gift['ip'] = ip
    ctx.gift['port'] = port
    if s is None:
        ctx.gift['io'] = remote(ip, port, timeout=ctx.gift['context_timeout'])
    else:
        s.connect((ip, port))
        ctx.gift['io'] = remote.fromsocket(s)
    ctx._log("connect {} port {} success!".format(ip, port))

    if ctx.fromcli:
        ctx.gift['io'].interactive()
    else:
        threading.Thread(target=lambda :CurrentGadgets.reset(), daemon=True).start()


_proxy_mode_list = ['undefined', 'notset', 'default', 'primitive']

@click.command(name='remote', short_help="Pwn remote host.")
@click.argument('filename', type=str, default=None, required=False, nargs=1)
@click.argument("target", required=False, nargs=1, default=None, type=str)
@click.option('-i', '--ip', default=None, show_default=True, type=str, nargs=1, help='The remote ip addr.')
@click.option('-p', '--port', default=None, show_default=True, type=int, nargs=1, help='The remote port.')
@click.option('-P', '-up', '--use-proxy', is_flag=True, show_default=True, help="Use proxy or not.")
@click.option('-m', '-pm', '--proxy-mode', type=click.Choice(_proxy_mode_list), show_default=True, default='undefined', help="Set proxy mode. undefined: read proxy data from config data(do not set this type in your file); notset: not use proxy; default: pwntools context proxy; primitive: pure socks connection proxy.")
@click.option('-n', '-nl', '--no-log', is_flag=True, show_default=True, help="Disable context.log or not.")
@click.option('-v', '--verbose', count=True, help="Show more info or not.")
@pass_environ
def cli(ctx, filename, target, ip, port, verbose, use_proxy, proxy_mode, no_log):
    """FILENAME: ELF filename.\n
    TARGET: Target victim.

    \b
    For remote target:
        pwncli -v remote ./pwn 127.0.0.1:23333 -up --proxy-mode default
    Or to specify the ip and port:
        pwncli -v remote -i 127.0.0.1 -p 23333
    """
    ctx.vlog("Welcome to use pwncli-remote command~")
    if not ctx.verbose:
        ctx.verbose = verbose
    if verbose:
        ctx.vlog("remote-command --> Open 'verbose' mode")

    ctx.vlog("remote-command --> Get 'no-log': {}".format(no_log))
    ctx.gift['remote'] = True

    # set ip from config data
    if ip is None:
        ip = try_get_config_data_by_key(ctx.config_data, 'remote', 'ip')

    if use_proxy and proxy_mode == "undefined": # set proxy mode in remote from config data
        _proxy_mode = try_get_config_data_by_key(ctx.config_data, 'remote', 'proxy_mode')
        if _proxy_mode is not None and _proxy_mode.lower() in _proxy_mode_list[1:]:
            proxy_mode = _proxy_mode.lower()
        else:
            proxy_mode = 'notset'
            ctx.vlog2("remote-command --> Use proxy but proxy mode is not valid, choose 'notset' mode")
    
    if proxy_mode != "undefined":
        ctx.vlog("remote-command --> Use proxy, proxy mode: {}".format(proxy_mode))

    # set log level
    ll = 'error' if no_log else ctx.gift['context_log_level']
    context.update(log_level=ll)
    ctx.vlog("remote-command --> Set 'context.log_level': {}".format(ll))

    do_remote(ctx, filename, target, ip, port, proxy_mode)


    
