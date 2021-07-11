import click
import os
import sys
from collections import OrderedDict

__all__ = ['gift', 'cli']

gift = OrderedDict() # public property
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

_treasure  = OrderedDict() # internal property
_init_all = True # init all commands flag
class AliasedGroup(click.Group):
    def __init__(self, name=None, **attrs):
        click.Group.__init__(self, name, invoke_without_command=0,**attrs)
        self._all_commands = []
        self._used_commands = []
        # get all commands
        cmd_folder = os.path.abspath(os.path.join(os.path.dirname(__file__), "commands"))
        for filename in os.listdir(cmd_folder):
            if filename.endswith(".py") and filename.startswith("cmd_"):
                self._all_commands.append(filename[4:-3])
        if len(self._all_commands) == 0:
            raise click.Abort("No command!")
        self._all_commands.sort()
        if _init_all:
            self._used_commands = self._all_commands
        

    def add_command(self, name:str=None):
        """add all commands from folder `commands`"""
        if name is None:
            self._used_commands = self._all_commands
            return
        
        if name not in self._all_commands:
            raise click.Abort("No command named %s" % name)
        
        if name not in self._used_commands:
            self._used_commands.append(name)
            self._used_commands.sort()
        

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
        ctx.abort('cli --> Too many matches: %s' % ', '.join(sorted(matches)))
        
        

class Environment:
    global gift, _treasure
    def __init__(self):
        self.gift = gift
        self._treasure = _treasure
        pass

    def abort(self, msg=None, **args):
        if args:
            msg %= args
        click.secho("[---] Abort: {}".format(msg), fg='black', bg='red', err=1)
        raise click.Abort()

    def _log(self, msg, *args):
        """Logs a message to stdout."""
        if args:
            msg %= args
        click.secho("[***] INFO: {}".format(msg), fg='green')

    def _log2(self, msg, *args):
        """Logs an important message to stdout."""
        if args:
            msg %= args
        click.secho("[###] IMPORTANT INFO: {}".format(msg), fg='blue')

    def _errlog(self, msg, *args):
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
        if self.verbose:
            self._log2(msg, *args)

    def verrlog(self, msg, *args):
        """Logs a message to stderr only if verbose is enabled."""
        if self.verbose:
            self._errlog(msg, *args)


pass_environ = click.make_pass_decorator(Environment, ensure=True)

def _set_filename(ctx, filename, msg=None):
    if filename is not None:
        # set filename and check
        if os.path.exists(filename) and os.path.isfile(filename):
            ctx.filename = filename
            if not msg:
                ctx.vlog("cli --> Set 'filename': {}".format(filename))
            else:
                ctx.vlog(msg)
        else:
            ctx.abort("cli --> Wrong 'filename'!")


@click.command(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.option('-f', '--filename', type=str, default=None, show_default=True, help="Elf file path to pwn.")
@click.option('-ns', '--no-stop', is_flag=True, show_default=True, help="Use the 'stop' function or not.")
@click.option('-v', '--verbose', is_flag=True, show_default=True, help="Show more info or not.")
@pass_environ
def cli(ctx, filename, no_stop, verbose): # ctx: command property
    ctx.verbose = verbose
    ctx.fromcli = sys.argv[0].endswith('pwncli')
    if ctx.fromcli:
        ctx.vlog("cli --> Use 'pwncli' from command line")
    else:
        ctx.vlog("cli --> Use 'pwncli' from python script")
    if verbose:
        ctx.vlog("cli --> Open 'verbose' mode")
    _set_filename(ctx, filename)
    _treasure['no_stop'] = no_stop
    ctx.vlog("cli --> Set 'stop_function' status: {}".format("closed" if no_stop else "open"))




