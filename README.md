# pwncli - Do pwn by cool command line 
[EN](https://github.com/RoderickChan/pwncli/blob/main/README.md) | [ZH](https://github.com/RoderickChan/pwncli/blob/main/README-CN.md) | [API](https://github.com/RoderickChan/pwncli/blob/main/API-doc.md)


`pwncli` is a simple cli-tool for pwner, which can help you to write and debug your exploit effectively. You can use `pwncli` through command-line or in a python-script, and you can also use `pwncli` directly, just like `pwntools`. In addition, there are many practical functions and methods. 

Like `git`, `pwncli` contains a series of subcommands. Prefix subcommand is supported on `pwncli`. For example, there's a subcommand named `debug`, and you can use this subcommand by `pwncli debug xxxxx` or `pwncli de xxxxx` or `pwncli d xxxxx`. `pwncli` is able to recoginze the prefix characters and call `debug` command finally. However, if the prefix characters match two or more subcommands, an `MatchError` will be raised.

Furthermore, it's very easy to extend new commands on `pwncli` by adding your own subcommand file named `cmd_yourcmd.py` on directory `pwncli/commands`. `pwncli` detects and loads all subcommands automatically.

`pwncli` mainly depends on [click](https://github.com/pallets/click) and [pwntools](https://github.com/Gallopsled/pwntools). The former is a wonderful command line interface tool, and the latter is a helpful CTF-toolkit.

# Advantages
- write the script just one time, switch `debug` or `remote` mode using cool command
- set breakpoints or input other `gdb-commands` conveniently
- debug in tmux or wsl-terminal quickly
- more useful functions and tricks
- design costume commands easily

# Installation
`pwncli` is supported on any posix-like-distribution system, and `Ubuntu` is recommended. If you want to do pwn on `wsl` distrbutions(I suggest to use `wsl` because wsl-related options are designed), `Ubuntu-16.04/Ubuntu-18.04/Ubuntu-20.04` is a good choice. And you have to make sure your `wsl` distribution's name hasn't been changed because the default names are used to detect the `ubuntu.exe` files.
First, you need to install `click` and `pwntools` in a **python3** environment, and then install `pwncli` in current directory:
```
git clone https://github.com/RoderickChan/pwncli.git
cd ./pwncli
pip3 install --editable .
```

Of course, you can install it using pip: `pip3 install pwncli`.

and use `pwncli --version` to validate whether you install pwncli successfully.

# Usage
## pwncli
Get help messages of `pwncli` by exec `pwncli -h` or `pwncli --help`:
```
# pwncli -h

Usage: pwncli [OPTIONS] COMMAND [ARGS]...

  pwncli tools for pwner!

  For cli:
      pwncli -v subcommand args
  For python script:
      script content:
          from pwncli import *
          cli_script()
      then start from cli: 
          python3 yourownscript.py -v subcommand args

Options:
  -f, --filename TEXT  Elf file path to pwn.
  -g, --use-gdb        Always use gdb to debug.  [default: False]
  -ns, --no-stop       Use the 'stop' function or not. Only for debug-command
                       using python script.  [default: False]
  -v, --verbose        Show more info or not.
  -h, --help           Show this message and exit.

Commands:
  config    Get or set something about config data.
  debug     Debug the pwn file locally.
  patchelf  Patchelf executable file using glibc-all-in-one.
  remote    Pwn remote host.
```

## debug command
`debug` is a subcommand of `pwncli`, execute `pwncli debug -h` to get it's helpful document:
```
# pwncli debug -h

Usage: pwncli debug [OPTIONS] [FILENAME]

  FILENAME: The ELF filename.

  Debug in tmux:
      python3 exp.py debug ./pwn -t -gb malloc -gb 0x400789

Options:
  --argv TEXT                     Argv for process.
  -v, --verbose                   Show more info or not.
  -nl, --no-log                   Disable context.log or not.  [default:
                                  False]
  -t, --tmux                      Use tmux to gdb-debug or not.  [default:
                                  False]
  -w, --wsl                       Use wsl to pop up windows for gdb-debug or
                                  not.  [default: False]
  -m, --attach-mode [auto|tmux|wsl-b|wsl-u|wsl-o|wsl-wt]
                                  Gdb attach mode, wsl: bash.exe | wsl:
                                  ubuntu1234.exe | wsl: open-wsl.exe | wsl:
                                  wt.exe wsl.exe  [default: auto]
  -qg, --qemu-gdbremote TEXT      Only used for qemu, who opens the gdb
                                  listening port. Only tmux supported.Format:
                                  ip:port or only port for localhost.
  -gb, --gdb-breakpoint TEXT      Set gdb breakpoints while gdb-debug is used,
                                  it should be a hex address or '\$rebase'
                                  addr or a function name. Multiple
                                  breakpoints are supported.  [default: ]
  -gs, --gdb-script TEXT          Set gdb commands like '-ex' or '-x' while
                                  gdb-debug is used, the content will be
                                  passed to gdb and use ';' to split lines.
                                  Besides eval-commands, file path is
                                  supported.
  -h, --help                      Show this message and exit.

```

## remote command
```
# pwncli remote -h

Usage: pwncli r [OPTIONS] [FILENAME] [TARGET]

  FILENAME: ELF filename.

  TARGET: Target victim.

  For remote target:
      pwncli -v remote ./pwn 127.0.0.1:23333 -up --proxy-mode default
  Or to Specify the ip and port:
      pwncli -v remote -p 23333

Options:
  -v, --verbose                   Show more info or not.  [default: False]
  -up, --use-proxy                Use proxy or not.  [default: False]
  -pm, --proxy-mode [notset|default|primitive]
                                  Set proxy mode. default: pwntools context
                                  proxy; primitive: pure socks connection
                                  proxy.  [default: notset]
  -i, --ip TEXT                   The remote ip addr.
  -p, --port INTEGER              The remote port.
  -h, --help                      Show this message and exit.
```

## patchelf command
Make sure you use `glibc-all-in-one` to organize all libc files so the path of libc.so.6 is normalized, for example, it's `~/glibc-all-in-one/libs/2.32-0ubuntu3.2_amd64/libc-2.32.so`. This command helps you patch elf quickly.
```
Usage: pwncli patchelf [OPTIONS] FILENAME LIBC_VERSION

  FILENAME: ELF executable filename.

  LIBC_VERSION: Libc version.

  pwncli patchelf ./filename 2.29 -b

Options:
  -b, --back-up             Backup target file or not.
  -f, --filter-string TEXT  Add filter condition.
  -h, --help                Show this message and exit.
```

## config file
A config file will be read if it exists. The path is `~/.pwncli.conf`.

`pwncli` reads data from config file if some option values are not given.

The example of `~/.pwncli.conf`:
```
[context]
log_level=error
timeout=3


[remote]
ip=127.0.0.1
proxy_mode=default


[proxy]
type=http
host=localhost
port=80
username=admin
passwd=admin123
rdns=True
```

## examples and screenshots
### use `debug` command through cli
There is an elf file named `pwnme` and your `exp.py`.

When you are in a tmux window and you want to set a breakpoint at `malloc` and `free`:
```
pwncli -v debug ./pwnme -t -gb malloc -gb free
``` 

or to specify your gdb-script path `./script`:
```
pwncli -v debug ./pwnme -t -gs "./script"
```

When you use `wsl` and `open-wsl.exe` to debug pwn file and wanner exec two or more gdb commands:
```
pwncli -v debug ./pwnme -w -a wsl-o -gs "b malloc;b free;directory /usr/src/glibc/glibc-2.23/malloc"
```

### use `debug` command through python-script
Content of your own script `exp.py`:
```python
#!/usr/bin/python3
from pwncli import *

cli_script()

if gift['debug']:
    elf = gift['elf']
    libc = gift['libc']
elif gift['remote']:
    libc = ELF('./libc-2.23.so')

# get tube
p:tube = gift['io']

#send and recv
p.sendlineafter('xxx', payload)
msg = p.recvline()

# stop to debug
stop() 

# log address
leak_addr = u64(p.recvn(8))
log_address('leak_addr', leak_addr)

# keep tube alive
p.interactive()
```
and then, use your script on cli:
```
./exp.py debug ./pwnme -t -gb malloc
```
or:
```
python3 exp.py -v de ./pwnme -w -gb "\$rebase(0xdead)"
```

### use `remote` command
Specify ip and port:
```
pwncli remote ./pwnme 127.0.0.1:23333
```

If the default ip has been given in `~/.pwncli.conf`, you can just input the port:
```
pwncli remote -p 23333
```

Use proxy, the proxy data must be written in `~/.pwncli.conf`:
```
pwncli re --use-proxy --proxy-mode primitive
```
The `default` proxy is to set `context.proxy`, and the `primitive` proxy is to use `remote.fromsocktet` and set proxy using `socks` and `socket` modules.
