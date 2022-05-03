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
from pwncli.utils.config import read_ini, try_get_config_data_by_key
from pwncli.utils.misc import log_ex, log2_ex, errlog_ex

__all__ = ['gift', 'cli_script']

class _Inner_Dict(OrderedDict):
    def __getattr__(self, name):
        if name not in self.keys():
            return None
        return self[name]
    
    def __setattr__(self, name, value):
        self[name] = value

gift = _Inner_Dict() # public property
_CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
_PWNCLI_DIR_NAME = os.path.dirname(os.path.abspath(__file__))

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
    global gift
    def __init__(self):
        self.gift = gift
        self.config_data = None
        self._log = log_ex
        self._log2 = log2_ex
        self._errlog = errlog_ex
    
    def get(self, item):
        return self.gift.get(item, None)

    def abort(self, msg=None, *args):
        if not msg:
            msg = "EXIT!"
        if args:
            msg %= args
        click.secho("[---] Abort: {}".format(msg), fg='black', bg='red', err=1)
        raise click.Abort()

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
@click.option('-v', '--verbose', count=True, help="Show more info or not.")
@click.version_option('1.2', "-V", "--version", prog_name='pwncli', message="%(prog)s: version %(version)s\nauthor: roderick chan\ngithub: https://github.com/RoderickChan/pwncli")
@pass_environ
def cli(ctx, filename, verbose): # ctx: command property
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
    ctx.fromcli = sys.argv[0].endswith(('/pwncli', '\\pwncli')) # Use this tool from cli or python script
    ctx.pwncli_path = _PWNCLI_DIR_NAME
    ctx.platform = sys.platform
    if verbose:
        ctx.vlog("cli --> Open 'verbose' mode")

    if ctx.fromcli:
        ctx.vlog("cli --> Use 'pwncli' from command line")
    else:
        ctx.vlog("cli --> Use 'pwncli' from python script. Please run 'cli_script()' to enable cli.")
        ctx.gift['no_stop'] = False
    _set_filename(ctx, filename)

    # init config file
    ctx.config_data = read_ini(os.path.expanduser('~/.pwncli.conf'))
    if ctx.config_data:
        ctx.vlog("cli --> Read config data from ~/.pwncli.conf success!")
    else:
        ctx.vlog2("cli --> Cannot read config data from ~/.pwncli.conf!")
    
    # read config data and set for debug and remote
    to = try_get_config_data_by_key(ctx.config_data, 'context', 'timeout')
    ctx.gift['context_timeout'] = to if to else 10 # set default timeout

    ll = try_get_config_data_by_key(ctx.config_data, 'context', 'log_level')
    ctx.gift['context_log_level'] = ll if ll else 'debug' # set default log_level


    # init debug/remote flag
    ctx.gift['debug'] = False
    ctx.gift['remote'] = False


def cli_script():
    cli.main(standalone_mode=False)



