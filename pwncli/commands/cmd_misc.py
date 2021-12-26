import click
import os
from pwncli.cli import pass_environ, AliasedGroup, _set_filename
from pwn import which

@click.command(cls=AliasedGroup, name='misc', short_help="Misc of useful sub-commands.")
@pass_environ
def cli(ctx):
    ctx.verbose = 2 # set verbose

@cli.command(name="gadget", short_help="Get all gadgets using ropper and ROPgadget, and then store them in files.")
@click.argument('filename', type=str, default=None, required=False, nargs=1)
@click.option('-a', '--all-gadgets', is_flag=True, show_default=True, help="Get all gadgets and don't remove duplicates.")
@click.option('-d', '--directory', type=str, default=".", required=False, help="The directory to save files.")
@pass_environ
def get_gadgets(ctx, filename, all_gadgets, directory):
    _set_filename(ctx, filename)
    
    if not ctx.get('filename'):
        ctx.abort("gadget-command ---> No filename, please specify the binary file.")
    
    if not os.path.isdir(directory):
        ctx.abort("gadget-command ---> The 'directory' is invalid.")
    
    ropper_path = which("ropper")
    ropgadget_path = which("ROPgadget")
    if not ropper_path and not ropgadget_path:
        ctx.verrlog("gadget-command ---> Cannot find ropper and ROPgadget in PATH, install them first.")
        s = input("Now install ropper and ROPgadget through pip3? [y/n]")
        if s.lower() == "y" or s.lower() == "yes":
            os.system("pip3 install ropper ROPgadget")
            ropper_path, ropgadget_path = 1, 1
        else:
            exit(-2)
    if ropper_path:
        cmd = "ropper -f {} --nocolor".format(filename)
        if all_gadgets:
            cmd += " --all"
        cmd += " > {}".format(os.path.join(directory, "ropper_gadgets"))
        ctx.vlog("gadget-command ---> Exec cmd: {}".format(cmd))
        os.system(cmd)

    if ropgadget_path:
        cmd = "ROPgadget --binary {}".format(filename)
        if all_gadgets:
            cmd += " --all"
        cmd += " > {}".format(os.path.join(directory, "ropgadget_gadgets"))
        ctx.vlog("gadget-command ---> Exec cmd: {}".format(cmd))
        os.system(cmd)