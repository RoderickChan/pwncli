import click
import sys
from pwncli.cli import pass_environ


@click.command(name='test', short_help="test command.")
@click.option('-v', '--verbose', is_flag=True, show_default=True, help="Show more info or not.")
@pass_environ
def cli(ctx, verbose):
    print("test...", verbose)
    pass