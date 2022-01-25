#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : cmd_config.py
@Time    : 2021/11/23 23:49:28
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : config subcommand
'''


import click
import sys
from pwncli.cli import pass_environ, AliasedGroup
from pwncli.utils.config import  *


@click.command(cls=AliasedGroup, name='config', short_help="Get or set something about config data.")
@pass_environ
def cli(ctx):
    ctx.verbose = 2
    pass


@cli.command(name="list", short_help="List config data.")
@click.argument("listdata", type=str, default=None, required=False, nargs=1)
@click.option('-s', '-sn', '--section-name', default=[], type=str, multiple=True, show_default=True, help="List config data by section name.")
@pass_environ
def list_config(ctx, listdata, section_name):
    """LISTDATA: List all data or example data or section names.
    """
    if listdata is None and len(section_name) == 0:
        ctx.vlog2("Use `pwncli config list all/example/section config data")
        return

    if listdata is not None:
        listdata = listdata.lower()
        if listdata == "all":
            ctx.vlog("config-command --> Show all config data in ~/.pwncli.conf")
            show_config_data_all(ctx.config_data)
        elif listdata == 'example':
            ctx.vlog("config-command --> Show example config data")
            show_config_data_file(os.path.join(ctx.pwncli_path, "conf/config_data.conf"))
        elif listdata == 'section':
             print("sections:", ctx.config_data.sections())
        else:
            ctx.verrlog("config-command --> Get error listdata '{}', must be 'all' or  'example' or 'section'".format(listdata))
        return
    
    for sec in section_name:
        if not ctx.config_data.has_section(sec):
            ctx.verrlog("config-command --> Error section name '%s'" % sec)
            continue
        show_config_data_by_section(ctx.config_data, sec)


def parse_clause_and_set(ctx, section_name:str, clause:str):
    from re import sub
    subwords = sub(r"\s*=\s*", "=", clause.strip()).split()
    for sc in subwords:
        if '=' not in sc:
            ctx.abort('config-command --> Error clause while setting config data, section: {} clause: {}'.format(section_name, clause))
        k, v = sc.split('=')
        set_config_data_by_key(ctx.config_data, section_name, k, v)
        ctx.vlog("config-command --> Set '{} = {}' for section [{}]".format(k, v, section_name))
    write_config_data(ctx.config_data)


@cli.command(name="set", short_help="Set config data.")
@click.argument("clause", type=str, default=None, required=False, nargs=1)
@click.option('-s', '-sn', '--section-name', default=None, type=str, show_default=True, help="Set config data by section name.")
@pass_environ
def set_config(ctx, section_name, clause):
    if (not section_name) or (not ctx.config_data.has_section(section_name)):
        ctx.verrlog("config-command --> Error section name '%s'" % section_name)
    else:
        parse_clause_and_set(ctx, section_name, clause)
