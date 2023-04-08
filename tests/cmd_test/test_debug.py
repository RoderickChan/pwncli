import os
import pathlib
import subprocess
import tempfile
import time

import pytest
from pwn import which

CURDIR = pathlib.Path(__file__).parent
pwnpath = CURDIR / "../sources/pwn"
pwnpath = str(pwnpath.resolve())
pwndir = str(CURDIR / "../sources")
libcpath = CURDIR / "../sources/libc-2.31.so"
libcpath = str(libcpath.resolve())

@pytest.mark.last
class TestDebug:
    def test_debug(self):
        if not which("tmux"):
            print("[!] Cannot test debug command, please install tmux.")
            return
        session_name = "test_debug"
        with tempfile.NamedTemporaryFile("w+t") as file:
            # open tmux
            os.system("tmux new-session -d -c %s -s %s" % (pwndir, session_name))
            filename = file.name
            cmd = "tmux send-keys -t %s:0.0 'pwncli de ./pwn' C-m" % session_name
            os.system(cmd)
            time.sleep(1)
            cmd = "tmux send-keys -t %s:0.0 admin C-m" % session_name
            os.system(cmd)
            time.sleep(1)
            cmd = "tmux send-keys -t %s:0.0 ' ' C-m" % session_name
            os.system(cmd)
            cmd = "tmux capture-pane -pS -10000 -t %s:0.0 > %s" % (session_name, filename)
            os.system(cmd)
            time.sleep(1)
            # close tmux
            os.system("tmux kill-session -t %s" % session_name)
            time.sleep(1)
            data = file.read()
            assert "flag{4f9861ef-1743-4cec-8b51-66f43d7099a2}" in data
        

    def test_debug_tmux(self):
        if not which("tmux") or not which("gdb"):
            print("[!] Cannot test debug command, please install tmux and gdb.")
            return
        session_name = "test_debug_tmux"
        with tempfile.NamedTemporaryFile("w+t") as file:
            # open tmux
            os.system("tmux new-session -d -c %s -s %s" % (pwndir, session_name))
            filename = file.name
            cmd = "tmux send-keys -t %s:0.0 'pwncli de ./pwn --tmux' C-m" % session_name
            os.system(cmd)
            time.sleep(5)
            cmd = "tmux send-keys -t %s:0.1 'set logging file %s' C-m" % (session_name, filename)
            os.system(cmd)
            cmd = "tmux send-keys -t %s:0.1 'set logging on' C-m" % session_name
            os.system(cmd)
            cmd = "tmux send-keys -t %s:0.1 'info registers' C-m" % session_name
            time.sleep(1)
            os.system(cmd)
            cmd = "tmux send-keys -t %s:0.1 'set logging off' C-m" % session_name
            os.system(cmd)
            time.sleep(1)
            
            # close tmux
            os.system("tmux kill-session -t %s" % session_name)
            time.sleep(1)

            data = file.read()
            assert "rax" in data
            assert "rbx" in data
            
    
