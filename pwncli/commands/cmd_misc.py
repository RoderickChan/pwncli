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
@click.option('-a', '--all', '--all-gadgets', "all_gadgets", is_flag=True, show_default=True, help="Get all gadgets and don't remove duplicates.")
@click.option('-d', '--dir', '--directory', "directory", type=str, default=".", required=False, help="The directory to save files.")
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


@cli.command(name="setgdb", short_help="Copy gdbinit files from and set gdb-scripts for current user.")
@click.option('-g', '--generate-script', "generate_script", is_flag=True, show_default=True, help="Generate the scripts of gdb-gef/gdb-pwndbg/gdb-peda in /usr/local/bin or not.")
@click.confirmation_option(prompt="Copy gdbinit files from pwncli/conf/.gdbinit-* to user directory?", expose_value=False)
@pass_environ
def copy_gdbinit(ctx, generate_script):
    if ctx.platform != "linux":
        ctx.abort("setgdb-command ---> This command can only be used in linux.")
    if generate_script and (os.getuid() != 0 or (os.getuid() == 0 and os.getenv("HOME").startswith("/root"))):
        ctx.abort("setgdb-command ---> Use `sudo' to run this command and make sure you are not root if you want to generate gdb-launching scripts.")
    
    cmd = "cp {} {}".format(os.path.join(ctx.pwncli_path, "conf/.gdbinit-*"), os.getenv("HOME"))
    ctx.vlog("setgdb-command ---> Exec cmd: {}".format(cmd))
    os.system(cmd)

    if generate_script:
        for name in ("pwndbg", "gef", "peda"):
            _cur_path = "/usr/local/bin/gdb-{}".format(name)
            with open(_cur_path, "wt", encoding="utf-8", errors="ignore") as file:
                file.write("#!/bin/sh\ncp ~/.gdbinit-{} ~/.gdbinit\nexec gdb \"$@\"\n".format(name))
                ctx.vlog("setgdb-command ---> Generate {} success.".format(_cur_path))
            os.system("chmod 755 {}".format(_cur_path))