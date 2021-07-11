import click
import sys
from pwncli.cli import pass_environ


@click.command(name='show', short_help="Show the pwnlib helpful parameters.")
@pass_environ
def cli(ctx):
    ctx.gift['show'] = True
    print("show...")
    pass