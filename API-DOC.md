# misc.py

## 数据处理

### int16
功能：`16`进制字符串转为十进制数字

示例：
```
x = int16("ff")
print(x)
# 255
```

### int8
功能：`8`进制字符串转为十进制数字

示例：
```
x = int8('77')
print(x)
# 63
```

### int2
功能：`2`进制字符串转为十进制数字

示例：
```
x = int2('1010')
print(x)
# 10
```

### int16_ex
功能：`16`进制字节或者字符串转为十进制数字

示例：
```
x = int16_ex(b"0xff")
y = int16_ex("0x10")
print(x, y)
# 255 16
```

### int8_ex
功能：`8`进制字节或者字符串转为十进制数字

示例：
```
x = int8_ex(b"77")
y = int8_ex("77")
print(x, y)
# 63 63
```

### int2_ex
功能：`2`进制字节或者字符串转为十进制数字

示例：
```
x = int2_ex(b"1010")
y = int2_ex("1010")
print(x, y)
# 10 10
```

### u16_ex
功能：将最多`2`个字节或者长度为`2`的字符串转换为整数，长度不足`2`的时候往左补`\x00`

示例：
```
x = u16_ex(b"a")
y = u16_ex("aa")
print(hex(x), hex(y))
# 0x61 0x6161
```

### float_hexstr2int

功能：



### protect_ptr

功能：将数据按`glibc2.32`的`tcache`加密规则（`safe-linking`）进行加密

参数：

+ `address`：对应`size`的`tcachebin`头节点
+ `next`：想加密的数据

返回值：一个整数

示例：

```python
>>> protect_ptr(0xdeadbeef,0xbeefdead)
3202495606
```

即：`(0xdeadbeef >> 12) ^ 0xbeefdead = 3202495606`

### reveal_ptr

功能：将数据按glibc2.32的tcache加密规则（safe-linking）进行解密，解出的是一个与加密前数据误差不大的值

参数：

+ 一个需要解密的地址

返回值：一个整数

示例：

```python
>>> reveal_ptr(3202495606) 
3202996971
>>> hex(3202996971)
'0xbee9daeb'
```

### pad_ljust



### pad_rjust



### p64_float

### generate_payload_for_connect

## 数据接收

### recv_libc_addr

功能：当接收到`/x7f`或`/xf7`时，根据设置的arch自动将包含"`/x7f`"在内的前3个字节/前6个字节解包为一个整数。

功能：当接收到`/x7f`或`/xf7`时，根据设置的arch自动将包含`/x7f`或`/xf7`在内的前3个字节/前6个字节解包为一个整数

参数：

+ `io(tube)`：一般会默认设置好的进程号，默认为通过pwncli de/re ./pwnfile 命令行起得进程
+ `bits(int, optional)`：一般会默认设置好的架构位数。32位架构与64位架构选其一
+ `offset(int, optional)`：解包后的整数要减去的偏移

返回值： 一个整数



## 日志打印

### log_ex

功能：打印参数内容至终端标准输出，内容前有提示符`[*] INFO`

参数：

+ `msg`：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

返回值：无

示例：

```python
打印一个字符串
>>log_msg = "hello_world"
>>log_ex(log_msg)
[*] INFO  hello_world

打印多个字符串
>>log_msg1 = "Hello"
>>log_msg2 = "Pwncli"
>>log_ex((log_msg1,log_msg2))
[*] INFO  ('hello', 'Pwncli')

利用格式化字符串
>>log_ex("hello %s,your age is %d","roderick",10)
[*] INFO  hello roderick,your age is 10
```

### log_ex_highlight

功能：打印参数内容至终端标准输出, 内容前面的提示符`[*] INFO`为白底绿字

参数：

+ `msg`：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

返回值：无

示例：

与`log_ex`的示例一致

### log2_ex

功能：打印参数内容至终端标准输出，内容前面的提示符为蓝色的`[#] IMPORTANT INFO`

参数：

+ `msg`：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

返回值：无

示例：

```text
打印一个字符串
>>log_msg = "hello_world"
>>log2_ex(log_msg)
[#] IMPORTANT INFO  hello_world

打印多个字符串
>>log_msg1 = "Hello"
>>log_msg2 = "Pwncli"
>>log2_ex((log_msg1,log_msg2))
[#] IMPORTANT INFO  ('hello', 'Pwncli')

利用格式化字符串
>>log2_ex("hello %s,your age is %d","roderick",10)
[#] IMPORTANT INFO  hello roderick,your age is 10
```

### log2_ex_highlight

功能：打印参数内容至终端标准输出, 内容前面的提示符`[#] IMPORTANT INFO`为白底蓝字

参数：

+ `msg`：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

返回值：无

示例：

与`log2_ex`的示例一致

### warn_ex

功能：打印参数内容至终端标准输出, 内容前面的提示符`[*]WARN`为黄字

参数：

+ `msg`：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

返回值：无

示例：

```text
>>warn_ex("hello %s,your age is %d","roderick",10)
[*] WARN  hello roderick,your age is 10
```

### warn_ex_highlight

功能：打印参数内容至终端标准输出, 内容前面的提示符`[*]WARN[!] ERROR`为白底黄字

参数：

+ `msg`：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

返回值：无

示例：无

### errlog_ex

功能：打印参数内容至终端标准输出, 内容前面的提示符`[!] ERROR`为红字

参数：

+ `msg`：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

返回值：无

示例：

```text
>>errlog_ex("hello %s,your age is %d","roderick",10)
[!] ERROR  hello roderick,your age is 10
```

### errlog_ex_highlight

功能：打印参数内容至终端标准输出, 内容前面的提示符`[!] ERROR`为白底红字

参数：

+ `msg`：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

返回值：无

示例：无

### errlog_exit

功能：打印参数内容至终端标准错误, 内容前面的提示符`[!] ERROR`为红字，然后退出

参数：

+ `msg`：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

返回值：无

示例：无

### errlog_ex_highlight_exit

功能：打印参数内容至终端标准错误, 内容前面的提示符`[!] ERROR`为白底红字，然后退出

参数：

+ `msg`：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

返回值：无

示例：无

### log_address

功能：打印参数内容至终端标准输出， 内容前面有提示符`[*] INFO`

参数：

+ `desc(str)`：对address参数的描述
+ `address(int)`：一个整数，打印出来时为16进制

返回值：无

示例：

```text
>>address = 0xdeadbeef
>>log_address("this is a address",address)
[*] INFO  this is a address ===> 0xdeadbeef
```

### log_address_ex

功能：搜索传入字符串并打印字符串对应变量名和变量值代表的地址内容至终端标准输出

参数：

+ `variable_name(str)`：变量名
+ `depth (int)`：默认是2。若该函数被封装n次，则为2+n

返回值：无

示例：

```text
>>address = 0xdeadbeef
>>log_address_ex("address")
```

### log_address_ex2

功能：搜索参数并打印参数名和参数值代表的地址内容至终端标准输出

参数：

+ `variable (int)`：变量
+ `depth (int)`：默认是2。若该函数被封装n次，则为2+n

返回值：无

示例：

```text
>>address = 0xdeadbeef
>>log_address_ex2(address)
[*] INFO  address ===> 0xdeadbeef
```

### log_libc_base_addr

功能：打印`libc`的基地址至终端标准输出

参数：

+ `address(int)`：一个代表libc的基地址的整数

返回值：无

示例：

```text
>>address = 0xdeadbeef
>>log_libc_base_addr(address)
[*] INFO  libc_base_addr ===> 0xdeadbeef
```

### log_heap_base_addr

功能：打印`heap`的基地址至终端标准输出

参数：

+ `address(int)`：一个代表heap的基地址的整数

返回值：无

示例：

```text
>>address = 0xdeadbeef
>>log_heap_base_addr(address)
[*] INFO  heap_base_addr ===> 0xdeadbeef
```

### log_code_base_addr

功能：打印程序的基地址至终端标准输出

参数：

+ `address(int)`：一个代表程序基地址的整数

返回值：无

示例：

```text
>>address = 0xdeadbeef
>>log_code_base_addr(address)
[*] INFO  code_base_addr ===> 0xdeadbeef
```

## libc-patch与one_gadget

### ldd_get_libc_path

功能：获得参数对应文件的`libc.so.6`的绝对地址

参数：

+ `filepath`：一个文件路径

返回值：文件所链接的`libc.so.6`的绝对地址

### one_gadget

功能：获得参数对应的`libc.so`的`one_gadget`

参数：

+ `condition`：一个libc.so文件的路径或build-id
+ `more`：调整搜索one_gadget参数，从而获得更多one_gadget

返回值：参数对应的libc.so中的one_gadget偏移

### one_gadget_binary

功能：获得参数对应的静态链接elf文件的one_gadget

参数：

+ binary_path：elf文件路径
+ more：调整搜索one_gadget参数，从而获得更多one_gadget

返回值：参数对应的静态链接elf文件的one_gadget偏移

## 堆记数相关

### calc_chunksize_corrosion



### calc_targetaddr_corrosion



### calc_idx_tcache



### calc_countaddr_tcache



### calc_entryaddr_tcache



### calc_countaddr_by_entryaddr_tcache



### calc_entryaddr_by_countaddr_tcache



# cli_misc.py

## 常用函数

### get_current_one_gadget_from_file

功能：获得当前运行的文件的one_gadget

参数：

+ libc_base：使搜索后的one_gadget都加上该值
+ more：调整搜索one_gadget参数，从而获得更多one_gadget

返回值：包含当前运行文件的所有one_gadget的一个列表

示例：无

### get_current_codebase_addr

功能：获得当前运行文件（进程）的代码段基地址

参数：

+ use_cache：默认true

返回值：一个代表代码段基地址的整数

示例：无

### get_current_libcbase_addr

功能：获得当前运行文件（进程）的libc段基地址

参数：

+ use_cache：

返回值：一个代表libc段基地址的整数

示例：无

### get_current_stackbase_addr

功能：获得当前运行文件（进程）的栈段基地址

参数：

+ use_cache：

返回值：一个代表栈段基地址的整数

示例：无

### get_current_heapbase_addr

功能：获得当前运行文件（进程）的堆段基地址

参数：

+ use_cache：

返回值：一个代表堆段基地址的整数

示例：无

## gdb相关

### kill_current_gdb

功能：运行到该函数时关闭gdb调试器

参数：

+ 无

返回值：无

示例：无

### execute_cmd_in_current_gdb

功能：运行到该函数时在gdb调试器中执行命令

参数：

+ str：要执行的命令，用";"或者"\n"分割多个命令

返回值：无

示例：无

### set_current_pie_breakpoints

功能：运行到该函数时通过传入偏移对开了pie的程序下断点（自动加上代码段基地址）

参数：

+ offset：要下断点的偏移

返回值：无

示例：无

### tele_current_pie_content

功能：：运行到该函数时查看开了pie的程序的数据

参数：

+ offset：要观察的地址
+ nember：显示数据的行数

返回值：无

示例：无

## 其他

### recv_current_libc_addr

功能：接收io所代表的进程的数据到`/x7f`或`/xf7`时，根据设置的arch自动将包含"`/x7f`"在内的前3个字节/前6个字节解包为一个整数

参数：

+ offset：打包后要减去的整数，默认为0
+ timeout：等待时间，默认为5

返回值：一个整数

示例：无

### get_current_flag_when_get_shell

功能：当攻击成功获得shell的时候，进行获得flag操作

参数：

+ use_cat：使用cat /flag操作，默认为true
+ start_str：flag前缀，默认为flag{

返回值：flag字符串

示例：无

### set_current_libc_base

功能：设置libc的基地址，使得libc.sym.xxx操作会自动加上基地址

参数：

+ addr：获取到的libc地址，默认为0
+ offset：代表需要减去的值，可为函数名或整数

返回值：一个代表libc基地址的整数

示例：无

### set_current_libc_base_and_log

功能：设置libc的基地址并打印出该地址，并且使得libc.sym.xxx操作会自动加上基地址

参数：

+ addr：获取到的libc地址
+ offset：代表需要减去的值，可为函数名或整数

返回值：一个代表libc基地址的整数

示例：无

### set_current_code_base

功能：设置elf的基地址，使得elf.sym.xxx操作会自动加上基地址

参数：

+ addr：获取到的elf地址
+ offset：代表需要减去的值，可为函数名或整数

返回值：一个代表elf基地址的整数

示例：无

### set_current_code_base_and_log

功能：设置elf的基地址并打印出该地址，并且使得elf.sym.xxx操作会自动加上基地址

参数：

+ addr：获取到的elf地址
+ offset：代表需要减去的值，可为函数名或整数

返回值：一个代表elf基地址的整数

示例：无

### set_remote_libc

功能：设置攻击远程需要使用到的libc库

参数：

+ libc_so_patch：需要设置的libc库的地址

返回值：无

示例：无

### copy_current_io

功能：多用于爆破，将当前io fork，返回一个新的进程号

参数：

+ 无

返回值：新的进程号

示例：

```python
for i in range(0x10):
    try:
        new_func()
    except (EOFError):
        gift.io = copy_current_io()
```

# io_file.py

## io_file_attack

### house_of_apple2_execmd_when_exit

功能：生成进行house of apple2攻击以便getshell的payload，详情见：

https://www.roderickchan.cn/post/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2/

参数：

+ standard_FILE_addr：要确保该参数为`_IO_2_1_stdin_/_IO_2_1_stdout_/_IO_2_1_stderr_`其中一个的地址。若没办法，则该参数-0x30和-0x18处要为0
+ _IO_wfile_jumps_addr：_IO_wfile_jumps_的地址，一般设为 libc.sym._IO_wfile_jumps即可
+ system_addr：system函数的地址，一般设为libc.sym.system
+ cmd：要执行的shell指令，默认为sh

返回值：进行house of apple2攻击以便getshell的payload

示例：无

### house_of_apple2_stack_pivoting_when_exit

功能：生成house of apple2 栈迁移攻击的payload，详情见：

https://www.roderickchan.cn/post/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2/

参数：

+ `standard_FILE_addr`：要确保该参数为`_IO_2_1_stdin_/_IO_2_1_stdout_/_IO_2_1_stderr_`其中一个的地址。若没办法，则该参数-0x30和-0x18处要为0
+ `_IO_wfile_jumps_addr`：_IO_wfile_jumps_的地址，一般设为 libc.sym._IO_wfile_jumps即可
+ `leave_ret_addr`：代表leave_ret汇编指令的地址
+ `pop_rbp_addr`：代表poo rbp; ret汇编指令的地址
+ `fake_rbp_addr`：代表要迁移过去的地址 + 8（因为是通过leave;ret迁移）

返回值：`house of apple2` 栈迁移攻击的`payload`

示例：

```python
data = IO_FILE_plus_struct().house_of_apple2_stack_pivoting_when_exit(libc.sym._IO_2_1_stderr_,
                                                                      libc.sym._IO_wfile_jumps,
                                                                      libc.search(asm("leave; ret")).__next__(),
                                                                      libc.search(asm("pop rbp; ret")).__next__(),
                                                                      libc.sym._IO_2_1_stderr_ + 0xe0-8)
```



### payload_replace

功能：对数据对应偏移进行替换

参数：

+ `payload`：要进行替换的数据
+ `rpdict`：用`flat`生成的`payload`

返回值：替换好的数据

示例：

```python
data = IO_FILE_plus_struct().house_of_apple2_stack_pivoting_when_do_IO_operation(
    standard_FILE_addr=libc.sym._IO_2_1_stdout_,
    _IO_wfile_jumps_addr=libc.sym._IO_wfile_jumps,
    leave_ret_addr=lbs + 0x000000000004ae07,
    pop_rbp_addr=lbs + 0x0000000000023730,
    fake_rbp_addr=0xdeadbeef
)

data = payload_replace(data, {
    0x38: 0x7ffff7f957b0,
    0x10: mov_rdx2rsp,
    0x68: lbs + 0x00000000000f5d27
})
```

