import click
import sys
from pwncli.cli import pass_environ


@click.command(name='config', short_help="Get or set something about config data.")
@click.option('-l', '--list', type=str, default='all', required=False, show_default=True, help="List config data by section name.")
@click.option('-v', '--verbose', is_flag=True, show_default=True, help="Show more info or not.")
@pass_environ
def cli(ctx, list, verbose):
    print("config...", verbose)
    pass