#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : cmd_listen.py
@Time    : 2023/03/28 14:00:18
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : listen command
'''


import os

import click
from pwn import context, listen

from ..cli import _Inner_Dict, pass_environ


@click.command(name="listen", short_help="Listen on a port and spawn a program when connected.")
@click.option('-l', '--listen-once', "listen_one", is_flag=True, help="List once.")
@click.option('-L', '--listen-forever', "listen_forever", is_flag=True, help="List forever.")
@click.option('-p', '--port', "port", type=int, default=13337, help="List port.")
@click.option('-t', '--timeout', "timeout", type=int, default=300, help="List port.")
@click.option('-e', '--executable', "executable", type=str, default="", help="Executable file path to spawn.")
@click.option('-v', '--verbose', count=True, help="Show more info or not.")
@pass_environ
def cli(ctx, listen_one, listen_forever, port, timeout, executable, verbose):
    """
    \b
    pwncli listen -l
    pwncli listen -L
    pwncli listen -l -p 10001
    pwncli listen -l -vv -p 10001
    pwncli listen -l -vv -p 10001 -e /bin/bash # socat tcp-l:10001,fork exec:/bin/bash

    pwncli l -l
    """
    ctx.vlog("Welcome to use pwncli-listen command~")
    if not ctx.verbose:
        ctx.verbose = verbose
    if verbose:
        ctx.vlog("listen-command --> Open 'verbose' mode")

    if port < 1025:
        port = 13337
        ctx.vlog("listen-command ---> port must be larger than 1024.")
    if timeout < 1:
        timeout = 300
        ctx.vlog("listen-command ---> timeout must be a positive.")

    if executable:
        executable = executable.split()
        for exe_ in executable:
            if exe_:
                if os.path.exists(exe_) and os.path.isfile(exe_) and os.access(exe_, os.X_OK):
                    ctx.vlog2(
                        "listen-command ---> executable file check pass!.")
                else:
                    ctx.abort(
                        "listen-command ---> executable file check failed! path: {}".format(exe_))
    if (listen_one and listen_forever) or (not listen_one and not listen_forever):
        ctx.abort(
            "listen-command ---> listen_once and listen_forever cannot be specified or canceled at the same time")
    args = _Inner_Dict()
    args.listen_one = listen_one
    args.listen_forever = listen_forever
    args.port = port
    args.timeout = timeout
    args.executable = executable
    args.verbose = verbose
    for k, v in args.items():
        ctx.vlog("listen-command --> Set '{}': {}".format(k, v))

    if verbose:
        context.log_level = "debug"
    else:
        context.log_level = "error"

    def _f():
        ser = listen(port)
        if executable:
            ser.spawn_process(executable)
        ser.wait_for_connection()
        try:
            while ser.recv(4096, timeout=timeout):
                pass
        except:
            pass
        ser.close()

    while listen_forever:
        _f()
    else:
        _f()
