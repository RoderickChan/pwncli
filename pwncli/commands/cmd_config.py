import click
import sys
from pwncli.cli import pass_environ, AliasedGroup


@click.command(cls=AliasedGroup, name='config', short_help="Get or set something about config data.")
@click.option('-l', '--list', is_flag=True, show_default=True, help="List config data by section name or not.")
@click.option('-v', '--verbose', is_flag=True, show_default=True, help="Show more info or not.")
@pass_environ
def cli(ctx, list, verbose):
    print("config...", verbose)
    pass


@cli.command(name="set", short_help="Set config data.")
@pass_environ
def set_config(ctx):
    print("set conifg...")
    pass