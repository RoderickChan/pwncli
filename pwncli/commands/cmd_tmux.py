import functools
import inspect
import os
import signal
import threading
import time
from subprocess import getstatusoutput
from typing import List, TypedDict

import click

from pwncli.cli import _Inner_Dict, pass_environ


def return_self(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        func(self, *args, **kwargs)
        return self
    return wrapper

class _Command(TypedDict):
    name: str
    cmd: str


class _Pane(TypedDict):
    name: str
    fullname: str
    index: int
    command: _Command
    logged: bool
    logfile: str 

class _Window(TypedDict):
    name: str
    fullname: str
    index: int
    panes: List[_Pane]

class _Session(TypedDict):
    name: str
    windows: List[_Window]


class _Tmux:
    def __init__(self, ctx, args):
        self.ctx = ctx
        self._args = args
        status, _ = getstatusoutput("tmux -V")
        if status:
            self.ctx.abort("tmux-command --> Please install tmux to use 'pwncli tmux' command!")

        # Session
        self._sessions: _Session = _Session()
        self._cwd = os.getcwd()
    
    @return_self
    def get_new_session_name(self):
        i = -1
        sn = ""
        for i in range(1, 31):
            sn = "pwncli_{}".format(i)
            status, _ = getstatusoutput("tmux has-session {}".format(sn))
            if status:
                break
        if i > 30:
            self.ctx.abort("tmux-command --> Cannot create more than 30 tmux sessions")
        self.ctx.vlog("tmux-command --> Get new session name: {}".format(sn))
        self._sessions['name'] = sn
    
    def _process_args(self, commands, times, timeout, **kwargs):
        times = list(times)
        if len(commands) < 1:
            self.ctx.abort("tmux-command --> No command.")
        if len(times) < 1:
            times.append(1)

        if any(x < 1 for x in times):
            self.ctx.verrlog("tmux-command --> Detect invalid times")
        for i, t in enumerate(times):
            if t <= 0:
                times[i] = 1
        if len(times) < len(commands):
            lastone = times[-1]
            times += [lastone] * (len(commands) - len(times))
        elif len(times) > len(commands):
            for _ in range(len(times) - len(commands)):
                times.pop()


        self._args.times = tuple(times)
        
        if timeout <= 0:
            timeout = -1
        self._args.timeout = timeout
        # print(self._args)


    @return_self
    def process_args(self):
        self._process_args(**self._args)
    
    @return_self
    def build_sessions(self):
        cmd_prefix = "" # "cd {} && ".format(self._cwd)
        all_cmds = []
        for i, c in enumerate(self._args.commands):
            cmd = _Command(name="command%d" % (i + 1), cmd=cmd_prefix+c)
            all_cmds.append(cmd)
        # print(all_cmds)

        all_panes = []
        count_ = 0
        for i, t in enumerate(self._args.times):
            for _ in range(t):
                _pane = _Pane(name="pane%d" % (count_ + 1), command=all_cmds[i], 
                              logged=self._args.save_output, index=count_ % self._args.panes_per_window)
                all_panes.append(_pane)
                count_ += 1
        # print(all_panes)
        all_windows = []
        for i in range(0, count_, self._args.panes_per_window):
            idx = i // self._args.panes_per_window
            _win = _Window(name="window%d" % (idx + 1), index=idx, panes=all_panes[i:i+self._args.panes_per_window])
            all_windows.append(_win)
            
        self._sessions["windows"] = all_windows
        
    @return_self
    def create_session(self):
        getstatusoutput("tmux new-session -s {} -d -c {}".format(self._sessions["name"], self._cwd))
    
    @return_self
    def create_windows(self):
        all_windows = self._sessions["windows"]
        getstatusoutput("tmux rename-window -t {}:0 {}".format(self._sessions["name"], all_windows[0]["name"]))
        for w in all_windows[1:]:
            getstatusoutput("tmux new-window -t {} -n {} -c {}".format(self._sessions["name"], w["name"], self._cwd))
    
    @return_self
    def create_panes(self):
        curdir = os.getcwd()
        ops = ((0, "-h"),
               (0, "-v"),
               (2, "-v"),
               (0, "-h"),
               (2, "-h"),
               (4, "-h"),
               (6, "-h"))
        for w in self._sessions["windows"]:
            for p in w["panes"]:
                p["logfile"] = os.path.join(curdir, "{}-{}-{}.log".format(self._sessions["name"], w["name"], p["name"]))
                w["fullname"] = "{}:{}".format(self._sessions["name"], w["name"])
                p["fullname"] = "{}:{}.{}".format(self._sessions["name"], w["name"], p["index"])
                if p["index"] == 0:
                    continue
                getstatusoutput("tmux splitw -t {}:{}.{} {} -c {}".format(self._sessions["name"], w["name"], ops[p["index"]-1][0], ops[p["index"]-1][1], self._cwd))
    
    @staticmethod
    def execuate_single_cmd(p: _Pane):
        if p["logged"]:
            getstatusoutput("tmux pipe-pane -t {} \"cat > {}\"".format(p["fullname"], p["logfile"]))
        getstatusoutput("tmux send-keys -t {} '{}' Enter".format(p["fullname"], p["command"]["cmd"]))
        time.sleep(1)
        
    @staticmethod
    def timeout(signum, frame):
        self = frame.f_locals["self"]
        if self._args.kill_after_detach:
            getstatusoutput("tmux kill-session -t {}".format(self._sessions["name"]))
        raise TimeoutError()
    
    def execuate_cmds(self):
        all_threads = []
        for w in self._sessions["windows"]:
            for p in w["panes"]:
                t = threading.Thread(target=self.execuate_single_cmd, args=(p,), daemon=True)
                t.start()
                all_threads.append(t)
                
        
        if self._args.timeout > 0:
            signal.signal(signal.SIGALRM, self.timeout)
            signal.alarm(self._args.timeout)
            self.ctx.vlog("tmux-command --> Alarm starts, set timeout: {}".format(self._args.timeout))
        
        if self._args.attach:
            self.ctx.vlog("tmux-command --> Try to attach session {}".format(self._sessions["name"]))
            remain = signal.alarm(0)
            getstatusoutput("tmux attach-session -t {} || tmux switch-client -t {}".format(self._sessions["name"], self._sessions["name"]))
            signal.alarm(remain)
            if self._args.kill_after_detach:
                getstatusoutput("tmux kill-session -t {}".format(self._sessions["name"]))
                self.ctx.vlog("tmux-command --> Kill session {}".format(self._sessions["name"]))
            
        for t in all_threads:
            if t.is_alive():
                t.join()

@click.command(name='tmux', short_help="Use tmux to execuate command many times.")
@click.option('-c', '--cmd', '--command', "commands", default=[], type=str, multiple=True, show_default=False, help="The commands you want to execuate.")
@click.option('-t', '--times', "times", default=[], type=int, multiple=True, show_default=False, help="The times of commands that you want to repeat.")
@click.option('-p', '--panes-per-window', "panes_per_window", type=click.IntRange(1, 8, True), default=1, show_default=True, help="The number of panes in each window.")
@click.option('-T', '--timeout', "timeout", type=int, default=-1, show_default=False, help="Close the session when timeout, -1 means no timeout.")
@click.option('-s', '--save', '--save-output', "save_output", is_flag=True, show_default=True, help="Save output for panes.")
@click.option('-a', '--attach', "--attach-session", "attach", is_flag=True, show_default=True, help="Attach session or not")
@click.option('-k', '--kill', "--kill-after-detach", "kill_after_detach",is_flag=True, show_default=True, help="Save output for panes.")
@click.option('-v', '--verbose', count=True, show_default=True, help="Show more info or not.")
@pass_environ
def cli(ctx, verbose, commands, times, panes_per_window, timeout, save_output, attach, kill_after_detach):
    """
    Execuate command use tmux.
    
    \b
    For example: pwncli tmux -c "python3 ./exp.py re ./pwn 127.0.0.1 13337" -t 4 -p 4
    
    \b
    Execuate 'ls -alh' in four windows:
        pwncli tmux -c "ls -alh" -t 4
    Execuate 'ls -al' three times, each pane execuate one commnad, three panes in one window:
        pwncli tmux -c "ls -al" -t 3 -p 3
        pwncli tmux -c "ls -al" -t 3 -p 1 # one pane in one window
    Execuate 'ls -al' two times, execuate 'date' three times, each pane execuate one commnad, four panes in one window:
        pwncli tmux -c "ls -alh" -t 2 -c "date" -t 3 -p 4
    
    """
    if not ctx.verbose:
        ctx.verbose = verbose
    if verbose:
        ctx.vlog("tmux-command --> Open 'verbose' mode")

    cf = inspect.currentframe().f_code.co_filename
    sig = ""
    with open(cf, "rt", encoding="utf-8") as fp:
        find_cli = False
        for line in fp:
            line = line.strip()
            if line.startswith("def cli"): 
                find_cli = True
                
            if find_cli:
                sig += line
                if line.endswith("):"):
                    break
    
    li = sig.index("(")
    hi = sig.index(")")
    args = _Inner_Dict()
    for _arg in sig[li+1:hi].split(","):
        _arg = _arg.strip()
        if _arg in ("ctx", "verbose"):
            continue
        args[_arg] = locals()[_arg]    
        ctx.vlog("tmux-command --> Get '{}': {}".format(_arg, args[_arg]))

    _tmux = _Tmux(ctx, args)
    _tmux.process_args()\
        .get_new_session_name()\
        .build_sessions()\
        .create_session()\
        .create_windows()\
        .create_panes()\
        .execuate_cmds()