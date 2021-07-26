import click
import sys
from pwncli.cli import pass_environ, AliasedGroup


@click.command(cls=AliasedGroup, name='config', short_help="Get or set something about config data.")
@pass_environ
def cli(ctx,):
    print("config...")
    pass



@cli.command(name="list", short_help="List config data.")
@click.argument("listdata", type=str, default=None, required=False, nargs=1)
@click.option('-s', '--section', is_flag=True, show_default=True, help="List config data by section name or not.")
@pass_environ
def list_config(ctx, listdata, section):
    print("list conifg...")
    pass


@cli.command(name="set", short_help="Set config data.")
@pass_environ
def set_config(ctx):
    print("set conifg...")
    pass