import click
from pwncli.cli import pass_environ, _set_filename
from pwn import remote, ELF


def do_remote(ctx, filename, target, ip, port):
    if getattr(ctx, 'filename', None) is None:
        _set_filename(ctx, filename, msg="remote-command --> Set 'filename': {}".format(filename))
        ctx.gift['elf'] = ELF(filename)
        ctx.gift['libc'] = ctx.gift['elf'].libc
    
    if target:
        ip, port = target.strip().split(';')
        ip = ip.strip()
        port = int(port)
        ctx.vlog("remote-command --> Get 'target': {}".format(target))
    elif ip and port:
        ctx.vlog("remote-command --> Get 'ip': {}".format(ip))
        ctx.vlog("remote-command --> Get 'port': {}".format(port))
    else:
        ctx.abort("remote-command --> Cannot get the victim host!")
    
    # little check
    if ip is None or len(ip) == 0 or port <= 0:
        ctx.abort("remote-command --> Cannot get the victim host!")

    r = remote(ip, port)
    ctx.gift['io'] = r

    if ctx.fromcli:
        r.interactive()


@click.command(name='remote', short_help="Pwn remote host.")
@click.argument("target", required=False, nargs=1, default=None, type=str)
@click.option('-f', '--filename', type=str, default=None, show_default=True, help="Elf file path to pwn.")
@click.option('-i', '--ip', default=None, show_default=True, type=str, nargs=1, help='The remote ip addr.')
@click.option('-p', '--port', default=None, show_default=True, type=int, nargs=1, help='The remote port.')
@click.option('-v', '--verbose', is_flag=True, show_default=True, help="Show more info or not.")
@pass_environ
def cli(ctx, filename, target, ip, port):
    """TARGET: Target victim.

    \b
    For remote target:
        pwncli -v remote -f ./pwn 127.0.0.2:23333
    Or to Specify the ip and port:
        pwncli -v remote -i 127.0.0.1 -p 23333
    """
    ctx.vlog("Welcome to use pwncli-remote command~")
    if not ctx.verbose:
        ctx.verbose = verbose
    if verbose:
        ctx.vlog("remote-command --> Open 'verbose' mode")

    ctx.vlog("remote-command --> Get 'filename': {}".format(filename))
    ctx.gift['remote'] = True
    do_remote(ctx, filename, target, ip, port)
    
    
    pass