import click
import sys
from pwncli.cli import pass_environ

def callback_verbose(ctx, param, value):
    if value:
        return value

@click.command(name='show', short_help="Show the pwnlib helpful parameters.")
@click.option('-v', '--verbose', is_flag=True, show_default=True,callback=callback_verbose, help="Show more info or not.")
@pass_environ
def cli(ctx, verbose):
    print("show...", verbose)
    pass