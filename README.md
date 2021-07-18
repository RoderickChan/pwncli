# pwncli - Do pwn by cool command line 
`pwncli` is a simple cli tool for pwner, which can help you to write and debug your exploit effectively. You can use `pwncli` through command-line or other python-script. 

Furthermore, it's very easy to extend new commands on `pwncli` by adding your own sub-command file named `cmd_yourcmd.py` on directory `pwncli/commands`. `pwncli` detects and loads commands automatically.

`pwncli` depends on [click](https://github.com/pallets/click) and [pwntools](https://github.com/Gallopsled/pwntools). The former is a wonderful command line interface tool, and the latter is a helpful CTF-toolkit.

# Installation
`pwncli` is supported on any posix-like-distribution system. If you want to do pwn on `wsl` distrbution, `Ubuntu-16.04/Ubuntu-18.04/Ubuntu-20.04` is a good choice. And you have to make sure your `wsl` distribution name hasn't been changed.
Your need to install `click` and `pwntools` first, and then install `pwncli`:
```
git clone https://github.com/RoderickChan/pwncli.git
cd ./pwncli
pip3 install --editable .
```

