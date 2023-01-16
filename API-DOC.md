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

+ io(tube)：一般会默认设置好的进程号，默认为通过pwncli de/re ./pwnfile 命令行起得进程
+ bits(int, optional):一般会默认设置好的架构位数。32位架构与64位架构选其一
+ offset(int, optional)：解包后的整数要减去的偏移

返回值： 一个整数



## 日志打印

### log_ex

功能：打印参数内容至终端标准输出，内容前有提示符`[*] INFO`

参数：

+ msg：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

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

+ msg：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

返回值：无

示例：

与`log_ex`的示例一致

### log2_ex

功能：打印参数内容至终端标准输出，内容前面的提示符为蓝色的`[#] IMPORTANT INFO`

参数：

+ msg：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

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

+ msg：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

返回值：无

示例：

与`log2_ex`的示例一致

### warn_ex

功能：打印参数内容至终端标准输出, 内容前面的提示符`[*]WARN`为黄字

参数：

+ msg：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

返回值：无

示例：

```text
>>warn_ex("hello %s,your age is %d","roderick",10)
[*] WARN  hello roderick,your age is 10
```

### warn_ex_highlight

功能：打印参数内容至终端标准输出, 内容前面的提示符`[*]WARN[!] ERROR`为白底黄字

参数：

+ msg：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

返回值：无

示例：无

### errlog_ex

功能：打印参数内容至终端标准输出, 内容前面的提示符`[!] ERROR`为红字

参数：

+ msg：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

返回值：无

示例：

```text
>>errlog_ex("hello %s,your age is %d","roderick",10)
[!] ERROR  hello roderick,your age is 10
```

### errlog_ex_highlight

功能：打印参数内容至终端标准输出, 内容前面的提示符`[!] ERROR`为白底红字

参数：

+ msg：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

返回值：无

示例：无

### errlog_exit

功能：打印参数内容至终端标准错误, 内容前面的提示符`[!] ERROR`为红字，然后退出

参数：

+ msg：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

返回值：无

示例：无

### errlog_ex_highlight_exit

功能：打印参数内容至终端标准错误, 内容前面的提示符`[!] ERROR`为白底红字，然后退出

参数：

+ msg：要输出内容, 可利用格式化字符串。如果需要输出多个内容，则需要用括号将参数括起来

返回值：无

示例：无

### log_address

功能：打印参数内容至终端标准输出， 内容前面有提示符`[*] INFO`

参数：

+ desc(str)：对address参数的描述
+ address(int)：一个整数，打印出来时为16进制

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

+ variable_name（str)：变量名
+ depth (int)：默认是2。若该函数被封装n次，则为2+n

返回值：无

示例：

```text
>>address = 0xdeadbeef
>>log_address_ex("address")
```

### log_address_ex2

功能：搜索参数并打印参数名和参数值代表的地址内容至终端标准输出

参数：

+ variable (int)：变量
+ depth (int)：默认是2。若该函数被封装n次，则为2+n

返回值：无

示例：

```text
>>address = 0xdeadbeef
>>log_address_ex2(address)
[*] INFO  address ===> 0xdeadbeef
```

### log_libc_base_addr

功能：打印libc的基地址至终端标准输出

参数：

+ address(int)：一个代表libc的基地址的整数

返回值：无

示例：

```text
>>address = 0xdeadbeef
>>log_libc_base_addr(address)
[*] INFO  libc_base_addr ===> 0xdeadbeef
```

### log_heap_base_addr

功能：打印heap的基地址至终端标准输出

参数：

+ address(int)：一个代表heap的基地址的整数

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

+ address(int)：一个代表程序基地址的整数

返回值：无

示例：

```text
>>address = 0xdeadbeef
>>log_code_base_addr(address)
[*] INFO  code_base_addr ===> 0xdeadbeef
```

## libc-patch与one_gadget

### ldd_get_libc_path

功能：获得参数对应文件的libc.so.6的绝对地址

参数：

+ filepath：一个文件路径

返回值：文件所链接的libc.so.6的绝对地址

### one_gadget

功能：获得参数对应的libc.so的one_gadget

参数：

+ condition：一个libc.so文件的路径或build-id
+ more：调整搜索one_gadget参数，从而获得更多one_gadget

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

### get_current_one_gadget

与get_current_one_gadget_from_file使用一致

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



### get_current_flag_when_get_shell



### set_current_libc_base



### set_current_libc_base_and_log



### set_current_code_base



### set_current_code_base_and_log



### set_remote_libc



### copy_current_io



# io_file.py

## io_file_attack

### house_of_apple2_execmd_when_exit



### house_of_apple2_stack_pivoting_when_exit

功能：

参数：

+ 

返回值：

示例：
