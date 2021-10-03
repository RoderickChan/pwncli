""" pwncli main command module, the entry point is 'cli'

pwncli is a command-line tool for doing pwn attack using 'click' and 'pwntools' 
in CTF, and this tool can also be used through other python script. The goal of 
pwncli is "Just pwn, don't waste time on preparing exp".

Example of click is https://github.com/pallets/click/tree/main/examples/complex
Thanks fo click, it's a wonderful python-cli tool.
"""
import click
import os
import sys
from collections import OrderedDict
from pwncli.utils.config import read_ini

__all__ = ['gift', 'cli_script']

gift = OrderedDict() # public property
_CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
_PWNCLI_DIR_NAME = os.path.dirname(os.path.abspath(__file__))

_treasure  = OrderedDict() # internal property
_init_all_subcommands = True # init all commands flag


class AliasedGroup(click.Group):
    def get_command(self, ctx, cmd_name):
        cmd = click.Group.get_command(self, ctx, cmd_name)
        if cmd is not None:
            return cmd
        matches = [x for x in self.list_commands(ctx) if x.startswith(cmd_name)]
        if not matches:
            return None
        elif len(matches) == 1:
            return click.Group.get_command(self, ctx, matches[0])
        else:
            ctx.fail('\033[31mcli --> Too many matches: %s\033[0m' % ', '.join(sorted(matches)))


class CommandsAliasedGroup(click.Group):
    def __init__(self, name=None, **attrs):
        click.Group.__init__(self, name, **attrs)
        self._all_commands = []
        self._used_commands = []
        # get all commands
        cmd_folder = os.path.join(_PWNCLI_DIR_NAME, "commands")
        for filename in os.listdir(cmd_folder):
            if filename.endswith(".py") and filename.startswith("cmd_"):
                self._all_commands.append(filename[4:-3])
        if len(self._all_commands) == 0:
            raise click.Abort("No command!")
        self._all_commands.sort()
        if _init_all_subcommands:
            self._used_commands = self._all_commands
        

    def add_command(self, name:str=None):
        """add commands from folder `commands`"""
        if name is None:
            self._used_commands = self._all_commands
            return
        
        if name not in self._all_commands:
            raise click.Abort("No command named %s" % name)
        
        if name not in self._used_commands:
            self._used_commands.append(name)
            self._used_commands.sort()
        
    
    def del_command(self, name:str=None):
        """del command"""
        if name is None or (name not in self._used_commands):
            return
        self._used_commands.remove(name)


    def list_commands(self, ctx):
        return tuple(self._used_commands)


    def get_command(self, ctx, cmd_name):
        matches = [x for x in self._used_commands if x.startswith(cmd_name)]
        if not matches:
            return None
        elif len(matches) == 1:
            try:
                mod = __import__("pwncli.commands.cmd_{}".format(matches[0]), None, None, ["cli"])
            except ImportError:
                raise
            return mod.cli
        else:
            ctx.fail('\033[31mcli --> Too many matches: %s\033[0m' % ', '.join(sorted(matches)))
        
        

class Environment:
    global gift, _treasure
    def __init__(self):
        self.gift = gift
        self.treasure = _treasure
        self.config_data = None
        pass

    def abort(self, msg=None, *args):
        if not msg:
            msg = "EXIT!"
        if args:
            msg %= args
        click.secho("[---] Abort: {}".format(msg), fg='black', bg='red', err=1)
        raise click.Abort()

    @staticmethod
    def _log(msg, *args):
        """Logs a message to stdout."""
        if args:
            msg %= args
        click.secho("[***] INFO: {}".format(msg), fg='green')

    @staticmethod
    def _log2(msg, *args):
        """Logs an important message to stdout."""
        if args:
            msg %= args
        click.secho("[###] IMPORTANT INFO: {}".format(msg), fg='blue')

    @staticmethod
    def _errlog(msg, *args):
        """Logs a message to stderr."""
        if args:
            msg %= args
        click.secho("[!!!] ERROR: {}".format(msg), fg='red', err=1)

    def vlog(self, msg, *args):
        """Logs a message to stdout only if verbose is enabled."""
        if self.verbose:
            self._log(msg, *args)


    def vlog2(self, msg, *args):
        """Logs a message to stdout only if verbose is enabled."""
        if int(self.verbose) > 1:
            self._log2(msg, *args)


    def verrlog(self, msg, *args):
        """Logs a message to stderr only if verbose is enabled."""
        if self.verbose:
            self._errlog(msg, *args)


pass_environ = click.make_pass_decorator(Environment, ensure=True)

def _set_filename(ctx, filename, msg=None):
    if filename is not None:
        # set filename and check
        if os.path.isfile(filename):
            ctx.gift['filename'] = os.path.abspath(filename)
            if not msg:
                ctx.vlog("cli --> Set 'filename': {}".format(filename))
            else:
                ctx.vlog(msg)
        else:
            ctx.abort("cli --> Wrong 'filename'!")


@click.command(cls=CommandsAliasedGroup, context_settings=_CONTEXT_SETTINGS)
@click.option('-f', '--filename', type=str, default=None, show_default=True, help="Elf file path to pwn.")
@click.option('-g', '--use-gdb', is_flag=True, show_default=True, help="Always use gdb to debug.")
@click.option('-ns', '--no-stop', is_flag=True, show_default=True, help="Use the 'stop' function or not. Only for debug-command using python script.")
@click.option('-v', '--verbose', count=True, help="Show more info or not.")
@pass_environ
def cli(ctx, filename, use_gdb, no_stop, verbose): # ctx: command property
    """pwncli tools for pwner!

    \b
    For cli:
        pwncli -v subcommand args
    For python script:
        script content:
            from pwncli import *
            cli_script()
        then start from cli: 
            ./yourownscript -v subcommand args
    """
    ctx.verbose = verbose
    ctx.use_gdb = use_gdb
    ctx.fromcli = sys.argv[0].endswith('/pwncli') # Use this tool from cli or python script
    if use_gdb:
        ctx.vlog("cli --> Set 'use-gdb' flag")

    if verbose:
        ctx.vlog("cli --> Open 'verbose' mode")

    if ctx.fromcli:
        ctx.vlog("cli --> Use 'pwncli' from command line")
    else:
        ctx.vlog("cli --> Use 'pwncli' from python script. Please run 'cli_script()' to enable cli.")
        ctx.treasure['no_stop'] = no_stop
        ctx.vlog("cli --> Set 'stop_function' status: {}".format("closed" if no_stop else "open"))

    _set_filename(ctx, filename)

    # init config file
    ctx.config_data = read_ini(os.path.expanduser('~/.pwncli.conf'))
    if ctx.config_data:
        ctx.vlog("cli --> Read config data from ~/.pwncli.conf success!")
    else:
        ctx.vlog2("cli --> Cannot read config data from ~/.pwncli.conf!")

    # init debug/remote flag
    ctx.gift['debug'] = False
    ctx.gift['remote'] = False


def cli_script():
    cli.main(standalone_mode=False)



