import click
from pwncli.cli import pass_environ


@click.command(name='remote', short_help="Pwn remote host.")
@click.option('-i', '--ip', default=None, show_default=True, type=str, nargs=1, help='The remote ip addr.')
@click.option('-p', '--port', default=None, show_default=True, type=int, nargs=1, help='The remote port. Default value: None.')
@pass_environ
def cli(ctx):
    print("show...")
    pass