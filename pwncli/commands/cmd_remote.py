import click
import os
from collections import OrderedDict
from pwncli.cli import pass_environ, _set_filename
from pwn import remote, ELF,context
from pwncli.utils.config import *

def do_setproxy(ctx, proxy_mode):
    if proxy_mode == 'notset':
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
    proxy_port = int(proxy_setting['port']) if 'port' in proxy_setting else 80
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

    if getattr(ctx, 'filename', "error_file_name") == "error_file_name":
        _set_filename(ctx, filename, msg="remote-command --> Set 'filename': {}".format(filename))

    if filename:
        context.binary = ctx.filename
        ctx.gift['elf'] = ELF(filename)
        ctx.gift['libc'] = ctx.gift['elf'].libc
    
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
    if s is None:
        ctx.gift['io'] = remote(ip, port)
    else:
        s.connect((ip, port))
        ctx.gift['io'] = remote.fromsocket(s)

    if ctx.fromcli:
        ctx.gift['io'].interactive()


_proxy_mode_list = ['notset', 'default', 'primitive']

@click.command(name='remote', short_help="Pwn remote host.")
@click.argument('filename', type=str, default=None, required=False, nargs=1)
@click.argument("target", required=False, nargs=1, default=None, type=str)
@click.option('-v', '--verbose', count=True, help="Show more info or not.")
@click.option('-nl', '--nolog', is_flag=True, show_default=True, help="Disable context.log or not.")
@click.option('-up', '--use-proxy', is_flag=True, show_default=True, help="Use proxy or not.")
@click.option('-pm', '--proxy-mode', type=click.Choice(_proxy_mode_list), show_default=True, default='notset', help="Set proxy mode. default: pwntools context proxy; primitive: pure socks connection proxy.")
@click.option('-i', '--ip', default=None, show_default=True, type=str, nargs=1, help='The remote ip addr.')
@click.option('-p', '--port', default=None, show_default=True, type=int, nargs=1, help='The remote port.')
@pass_environ
def cli(ctx, filename, target, ip, port, verbose, use_proxy, proxy_mode, nolog):
    """FILENAME: ELF filename.\n
    TARGET: Target victim.

    \b
    For remote target:
        pwncli -v remote ./pwn 127.0.0.1:23333 -up --set-proxy=default
    Or to Specify the ip and port:
        pwncli -v remote -p 23333
    """
    ctx.vlog("Welcome to use pwncli-remote command~")
    if not ctx.verbose:
        ctx.verbose = verbose
    if verbose:
        ctx.vlog("remote-command --> Open 'verbose' mode")

    ctx.gift['remote'] = True

    # set ip from config data
    if ip is None:
        ip = try_get_config_data_by_key(ctx.config_data, 'remote', 'ip')

    # set proxy mode in remote from config data
    if not use_proxy:
        proxy_mode = "notset"
    elif proxy_mode == "notset":
        _proxy_mode = try_get_config_data_by_key(ctx.config_data, 'remote', 'proxy_mode')
        if _proxy_mode is not None and _proxy_mode.lower() in _proxy_mode_list:
            proxy_mode = _proxy_mode.lower()
        else:
            proxy_mode = 'default'
            ctx.vlog2("remote-command --> Use proxy but proxy mode is not given, choose default mode.")
    
    if proxy_mode != "notset":
        ctx.vlog("remote-command --> Use proxy, proxy mode: {}".format(proxy_mode))

    do_remote(ctx, filename, target, ip, port, proxy_mode)

        # set log level
    if nolog:
        ll = 'error'
    else:
        # try to set context from config data
        ll = try_get_config_data_by_key(ctx.config_data, 'context', 'log_level')
        if ll is None:
            ll = 'debug'
    context.update(log_level=ll)
    ctx.vlog("remote-command --> Set 'context.log_level': {}".format(ll))

    
