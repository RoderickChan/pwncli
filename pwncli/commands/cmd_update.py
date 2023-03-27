import click
import subprocess
import json
import os
import pathlib
from urllib import request
from pwncli.cli import pass_environ

def get_pypi_pwncli_info(ctx):
    url = "https://pypi.org/pypi/pwncli/json"
    with request.urlopen(url) as http:
        data = http.read()
        if http.status != 200:
            ctx.abort("update-command --> Cannot get pwncli info from %s", url)
        data = json.loads(data)
        version = data["info"]["version"]
        ctx.vlog("update-command --> Get pypi pwncli version: %s", version)
        return version


@click.command(name='update', short_help="Update pwncli.")
@click.option('-d', '--dir', "directory", default="", type=str, nargs=1, help="The directory of pwncli repository, it's used to execuate `git pull' command.")
@click.option('-v', '--verbose', count=True, help="Show more info or not.")
@pass_environ
def cli(ctx, directory, verbose):
    if not ctx.verbose:
        ctx.verbose = verbose
    if verbose:
        ctx.vlog("remote-command --> Open 'verbose' mode")
    install_from_git = False
    pwncli_install_from = subprocess.check_output("python3 -m pip freeze | grep pwncli", shell=True).decode()
    if "egg=pwncli" in pwncli_install_from:
        install_from_git = True
        ctx.vlog("update-command --> Detect that pwncli is installed from git")
    else:
        ctx.vlog("update-command --> Detect that pwncli is installed from pypi")
    
    if install_from_git:
        if not directory:
            directory = os.path.expanduser("~/pwncli")
        # check directory
        dirpath = pathlib.PosixPath(directory)
        if not dirpath.exists() or not dirpath.is_dir():
            ctx.abort("update-command --> Invalid pwncli directory %s, please specify the correct directory.", directory)
        
        cmd = "cd %s && git pull" % directory
        status, out = subprocess.getstatusoutput(cmd)
        ctx.vlog("update-command --> Execuate cmd '%s' to update pwncli.", cmd)
        if status:
            ctx.abort("update-command --> Execuate cmd error, output: %s" % out)
        else:
            ctx.vlog("update-command --> Update pwncli success!\n%s", out)
    else:
        remote_version = get_pypi_pwncli_info(ctx)
        local_version = pwncli_install_from.split("==")[1]
        if local_version < remote_version:
            cmd = "python3 -m pip install pwncli --upgrade"
            status, out = subprocess.getstatusoutput(cmd)
            ctx.vlog("update-command --> Execuate cmd '%s' to update pwncli.", cmd)
            if status:
                ctx.abort("update-command --> Execuate cmd error, output: %s" % out)
            else:
                ctx.vlog("update-command --> Update pwncli success!\n%s", out)
        else:
            ctx.vlog("update-command --> Noneed to update pwncli, local version: %s, remote version: %s", local_version, remote_version)