# pwncli -使用炫酷的命令行
`pwncli`可以帮助你快速编写`pwn`题攻击脚本，并实现本地调试和远程攻击的便捷切换。`pwncli`支持三种使用方式：命令行使用、脚本内使用与直接使用。其中，命令行使用不依托任何脚本，方便本地调试；脚本内使用可将脚本封装为命令行工具，然后调用子命令；直接使用则只调用一些工具函数，方便快速解题。

`pwncli`支持子命令的前缀匹配，通常只需要给出命令的前缀即可成功调用该命令。以`debug`命令为例，可以使用`pwncli debug ./pwn -t`，也可以使用`pwncli de ./pwn -t`进行本地调试。但是，必须保证前缀不会匹配到两个或多个子命令，否则将会抛出`MatchError`。 

此外，`pwncli`极易扩展。只需要在`pwncli/commands`目录下添加`cmd_xxx.py`，然后编写自己的子命令即可。`pwncli`会自动探测并加载子命令。

`pwncli`依赖于[click](https://github.com/pallets/click) 和 [pwntools](https://github.com/Gallopsled/pwntools)。前者是优秀的命令行编写工具，后者是大家普遍使用的`CTF-PWN`工具。

# 优点
- 脚本只需编写一次，使用命令行控制本地调试与远程攻击
- 方便设置断点与其他`gdb`命令
- 许多有用的小函数
- 轻松扩展并自定义子命令