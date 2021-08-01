import click
import sys
from pwncli.cli import pass_environ, AliasedGroup
from pwncli.utils.config import  *


@click.command(cls=AliasedGroup, name='config', short_help="Get or set something about config data.")
@pass_environ
def cli(ctx):
    ctx.verbose = True
    pass


@cli.command(name="list", short_help="List config data.")
@click.argument("listdata", type=str, default=None, required=False, nargs=1)
@click.option('-s', '--section-name', default=[], type=str, multiple=True, show_default=True, help="List config data by section name or not.")
@pass_environ
def list_config(ctx, listdata, section_name):
    """LISTDATA: List all data or example data or section names.
    """
    if listdata is None and len(section) == 0:
        ctx.vlog2("Use `pwncli config list all/example/section config data")
        return

    if listdata is not None:
        listdata = listdata.lower()
        if listdata == "all":
            ctx.vlog("config-command --> Show all config data in ~/.pwncli.conf")
            show_config_data_all(ctx.config_data)
        elif listdata == 'example':
            ctx.vlog("config-command --> Show example config data")
            show_config_data_file(os.path.abspath("../example/config_data.conf"))
        elif listdata == 'section':
             print("sections:", ctx.config_data.sections())
        else:
            ctx.verrlog("config-command --> Get error listdata '{}', must be 'all' or  'example'".format(listdata))
        return
    
    for sec in section_name:
        if not ctx.config_data.has_section(sec):
            ctx.vlog("config-command --> Error section name '%s'" % sec)
            continue
        show_config_data_by_section(ctx.config_data, sec)


@cli.command(name="set", short_help="Set config data.")
@click.argument("clause", type=str, default=None, required=False, nargs=1)
@pass_environ
def set_config(ctx):
    print("set conifg...")
    pass