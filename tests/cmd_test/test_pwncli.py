import os
import pytest

def test_version():
    assert os.system("pwncli --version") == 0
    assert os.system("pwncli -V") == 0

@pytest.mark.skip()
def test_allcmd():
    #[[master, sub]]
    cmds = [
        ["debug"],
        ["remote"],
        ["config", "list", "set"],
        ["initial"],
        ["misc", "gadget", "setgdb", "dstruct", "listen"],
        ["qemu"],
        ["template"],
        ["patchelf"]
    ]
    for item in cmds:
        cmd = item[0]
        assert os.system("pwncli {} --help".format(cmd)) == 0
        assert os.system("pwncli {} -h".format(cmd)) == 0
        if len(item) > 1:
            for subcmd in item[1:]:
                assert os.system("pwncli {} {} --help".format(cmd, subcmd)) == 0
                assert os.system("pwncli {} {} -h".format(cmd, subcmd)) == 0