import click
from pwncli.cli import pass_environ


@click.command(name='remote', short_help="Pwn remote host.")
@pass_environ
def cli(ctx):
    print("show...")
    pass