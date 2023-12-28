#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : decorates.py
@Time    : 2021/11/23 23:48:12
@Author  : Roderick Chan
@Email   : roderickchan@foxmail.com
@Desc    : Decorators
'''


import functools
import os
import signal
import sys
import time
from enum import Enum, unique

from pwn import ELF, process, remote, tube

try:
    from collections.abc import Iterable
except:
    from collections import Iterable

from inspect import signature
from itertools import product
from typing import Callable, List

from .exceptions import PwncliExit
from .misc import (errlog_exit, get_func_signature_str, ldd_get_libc_path,
                   log_ex, warn_ex_highlight)

__all__  = [
    'timer', 
    'sleep_call_before', 
    "sleep_call_after", 
    "sleep_call_all", 
    "sleeper",
    "bomber",
    "deprecated", 
    "unused",
    "show_name",
    "always_success",
    "limit_calls",
    "add_prompt",
    "cache_result",
    "cache_nonresult",
    "signature2name",
    "call_multimes",
    "count_calls",
    "convert_str2bytes",
    "convert_bytes2str"
    ]

# conver bytes type args to str
def convert_bytes2str(func):
    """A decorator.
    
    conver bytes type args to str"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        new_args = []
        for a in args:
            if isinstance(a, bytes):
                new_args.append(a.decode('latin-1'))
            else:
                new_args.append(a)
        new_kwargs = {}
        for k, v in kwargs.items():
            if isinstance(v, bytes):
                new_kwargs[k] = v.decode('latin-1')
            else:
                new_kwargs[k] = v
        return func(*new_args, **kwargs)
    return wrapper

# conver str type args to bytes
def convert_str2bytes(func):
    """A decorator.
    
    conver str type args to bytes"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        new_args = []
        for a in args:
            if isinstance(a, str):
                new_args.append(a.encode('latin-1'))
            else:
                new_args.append(a)
        new_kwargs = {}
        for k, v in kwargs.items():
            if isinstance(v, str):
                new_kwargs[k] = v.encode('latin-1')
            else:
                new_kwargs[k] = v
        return func(*new_args, **kwargs)
    return wrapper


def count_calls(show=True):
    """A decorator.
    
    Count how many times a function had been called.
    
    Use func._num_calls to get the times.

    Args:
        show (bool, optional): Show call times or not. Defaults to True.
    """
    def _wrapper(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            wrapper._num_calls += 1
            if show:
                print("Call {} of {}".format(wrapper._num_calls, func.__name__))
            return func(*args, **kwargs)
        wrapper._num_calls = 0
        return wrapper
    return _wrapper


def signature2name(func):
    """A decorator. 
    
    Make function's signature as its name"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        sig = get_func_signature_str(func.__name__, *args, **kwargs)
        wrapper.__name__ = sig
        return func(*args, **kwargs)
    return wrapper


def add_prompt(msg: str):
    """A decorator.

    Print message before call function.
    
    Args:
        msg (str): Message to stdout
    """
    def wrapper1(func):
        
        @functools.wraps(func)
        @signature2name
        def wrapper2(*args, **kwargs):
            sig = get_func_signature_str(func.__name__, *args, **kwargs)
            warn_ex_highlight("[call {}] prompt info --> {}".format(sig, msg))
            res = func(*args, **kwargs)
            return res
        return wrapper2
    return wrapper1


def always_success(show_err=False):
    """A decorator.

    Catch exception when call func. 
    
    Noye: Cannot deal with sys.exit.
    
    Args:
        show_err (bool, optional): Show error info or not. Defaults to False.
    """
    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            res = None
            try:
                res = func(*args, **kwargs)
            except Exception as e:
                if show_err:
                    warn_ex_highlight("error info: {}".format(e))
            return res
        return wrapper2
    return wrapper1


def deprecated(msg: str=""):
    """A decorator.

    Mark the function as deprecate and show message. 

    Args:
        msg (str, optional): Message to show. Defaults to "".
    """
    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            warn_ex_highlight("This function: {} is deprecated. {}".format(func.__name__, msg))
            res = func(*args, **kwargs)
            return res
        return wrapper2
    return wrapper1


def unused(msg: str=""):
    """A decorator.

    Mark the function as unused and show message. 

    Args:
        msg (str, optional): Message to show. Defaults to "".
    """
    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            warn_ex_highlight("This function: {} is unused and it would be removed in later version. {}".format(func.__name__, msg))
            return None
        return wrapper2
    return wrapper1


def limit_calls(times: int=1, warn_=True):
    """A decorator.
    
    Limite the times of calling a function.

    Args:
        times (int, optional): Times. Defaults to 1.
        warn_ (bool, optional): Show warn info or not. Defaults to True.

    """
    _tmp = 0
    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            nonlocal _tmp
            if _tmp < times:
                res = func(*args, **kwargs)
                _tmp += 1
            else:
                res = None
                if warn_:
                    warn_ex_highlight("This function {} has beed called for {} times, so it cannot be called any more.".format(func.__name__, times))
            return res
        return wrapper2
    return wrapper1

def call_multimes(times: int=1):
    """A decorator.
    
    Loop x times to call function 

    Args:
        times (int, optional): Times. Defaults to 1.
    """

    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            res = None
            for _ in range(times):
                res = func(*args, **kwargs)
            return res
        return wrapper2
    return wrapper1


def cache_result(func: Callable):
    """A decorator.
    
    Cache func's return value.
    
    That means the first return value will return when func is called again.
    """
    _res = None
    _flag = 0xdeadbeef
    @functools.wraps(func)
    def wrapper2(*args, **kwargs):
        nonlocal _flag, _res
        if _flag:
            _res = func(*args, **kwargs)
            _flag = 0
        return _res
    return wrapper2


def cache_nonresult(func: Callable):
    """A decorator.
    
    Only cache not None result.
    
    Once func returns the first Not None value, all next func calls will always return cache value. 

    """
    _res = None
    _flag = 0xdeadbeef
    @functools.wraps(func)
    def wrapper2(*args, **kwargs):
        nonlocal _flag, _res
        if _flag:
            _res = func(*args, **kwargs)
            if _res is not None:
                _flag = 0
        return _res
    return wrapper2


def show_name(func: Callable):
    """A decorator.

    Useful to fuzz.

    Show function's name when call a function.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        sig = get_func_signature_str(func.__name__, *args, **kwargs)
        log_ex("call {}".format(sig))
        res = func(*args, **kwargs)
        return res
    return wrapper


def timer(func):
    """A decorator.
    
    Count the time-consuming of a function

    Args:
        func ([type]): Func

    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        res = func(*args, **kwargs)
        end = time.time()
        sig = get_func_signature_str(func.__name__, *args, **kwargs)
        print('call {} execute time: {} s({} min)'.format(sig, end - start, (end - start) / 60))
        return res
    return wrapper


def bomber(seconds: int, callback=None):
    """A decorator.
    
    If the function does not finish running within the specified time, the program will exit and raise a TimeoutError.

    Args:
        seconds (int): Seconds to raise TimeoutError when timeout
        callback (Callable, optional): Callback when timeout, if callback is not None, return callback's retval. Defaults to None.
    """
    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            def handler(n, f):
                raise TimeoutError()
            sig = get_func_signature_str(func.__name__, *args, **kwargs)
            signal.signal(signal.SIGALRM, handler)
            signal.alarm(seconds)
            try:
                res = func(*args, **kwargs)
                signal.alarm(0)
            except TimeoutError:
                warn_ex_highlight("call %s Timeout!", sig)
                res = None
                if callback:
                    res = callback()
                else:
                    sys.exit(2)
            return res
        return wrapper2
    return wrapper1

@unique
class _SleepMode(Enum):
    BEFORE = 1
    AFTER = 2
    ALL = 3


def _sleep_call(second: int, mod: _SleepMode):
    """Sleep before and after call function

    Args:
        second (int, optional): Sleep time. Defaults to 1.
        mod (_SleepMode, optional): Sleep mode. Defaults to _SleepMode.BEFORE.
    """
    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            if mod.value & 1:
                time.sleep(second)
            res = func(*args, **kwargs)
            if mod.value & 2:
                time.sleep(second)
            return res

        return wrapper2

    return wrapper1


sleep_call_before = functools.partial(_sleep_call, mod=_SleepMode.BEFORE)

sleep_call_after = functools.partial(_sleep_call, mod=_SleepMode.AFTER)

sleep_call_all = functools.partial(_sleep_call, mod=_SleepMode.ALL)

sleeper = sleep_call_after


@unique
class _EnumerateAttackMode(Enum):
    LOCAL=0
    REMOTE=1


def _call_func_invoke(call_func, libc_path, loop_time, loop_list, tube_func, *tube_args):
    libc = ELF(libc_path)
    # print(tube_args)
    if loop_list:
        l_count = 0
        for iter_items in product(*loop_list):
            l_count += 1
            t = tube_func(*tube_args)
            libc.address = 0
            log_ex("[{}] ===> call func: {}, tube-args: {}, loop-args: {}".format(l_count, call_func.__name__, tube_args, iter_items))
            try:
                call_func(t, libc, *iter_items)
            except PwncliExit as ex:
                log_ex("Pwncli is exiting...ex info: {}".format(ex))
                break
            except KeyboardInterrupt:
                errlog_exit("KeyboardInterrupt!")
            except:
                pass
            finally:
                try:
                    t.close()
                except:
                    pass
    else:
        for i in range(loop_time):
            t = tube_func(*tube_args)
            libc.address = 0
            log_ex("[{}] ===> call func: {}, tube-args: {}".format(i+1, call_func.__name__, tube_args))
            try:
                call_func(t, libc)
            except PwncliExit as ex:
                log_ex("Pwncli is exiting...ex info: {}".format(ex))
                break
            except KeyboardInterrupt:
                errlog_exit("KeyboardInterrupt!")
                pass
            except:
                pass
            finally:
                try:
                    t.close()
                except:
                    pass


def _attack_local(argv, libc_path, call_func, loop_time, loop_list):
    # check para
    if argv is None or (not os.path.isfile(libc_path)) or loop_time <= 0 or call_func is None:
        raise RuntimeError("Para error! argv:{} libc_path:{} loop_time: {} call_func: {}".format(argv, libc_path, loop_time, call_func.__name__))
    _call_func_invoke(call_func, libc_path, loop_time, loop_list, process, argv)


def _attack_remote(libc_path, ip, port, call_func, loop_time, loop_list):
    if ip is None or port is None or (not os.path.isfile(libc_path)) or loop_time <= 0 or call_func is None:
        raise RuntimeError("Para error! is:{} port: {} libc_path:{} loop_time: {} call_func: {}".format(ip, port, libc_path, loop_time, call_func.__name__))
    _call_func_invoke(call_func, libc_path, loop_time, loop_list, remote, ip, port)


def _check_func_args(func_call, loop_list, check_first):
    assert func_call is not None and callable(func_call), "func_call {} error!".format(func_call)
    # check func_paras
    sig = signature(func_call)
    pars = sig.parameters
    com_help_info = "\n\t\t\tThe first para must be 'tube' type, the second one must be 'ELF' type for libc! If loop_list is specified, every element is a list or tuple."
    # if it has looplist, the length of func must be 2 + len(loop_list[0])
    if loop_list:
        assert isinstance(loop_list, (Iterable, list, tuple)), "  Loop_list is not tuple or list.\n"+com_help_info
        assert len(loop_list) > 0, "  Length of loop_list is 0.\n"+com_help_info
        for ll in loop_list:
            assert isinstance(ll, (Iterable, tuple, list)), "  An element of loop_list is not tuple or list.\n"+com_help_info
            assert len(ll) > 0, "  Length of an element of loop_list is 0.\n"+com_help_info
        # check paras len
        if check_first:
            assert len(pars) == (2 + len(loop_list)), "  Length of para is not {}.\n".format(2 + len(loop_list))+com_help_info
    else:
        if check_first:
            assert len(pars) == 2, "  Length of para is not 2.\n"+com_help_info

    if check_first:
        kl = []
        vl = []
        for k, v in pars.items():
            kl.append(k)
            vl.append(v)

        assert (issubclass(vl[0].annotation, tube)) and (issubclass(vl[1].annotation, ELF)), "  Type of {} is: {}, type of {} is {}.".format(kl[0],
            vl[0].annotation, kl[1], vl[1].annotation)+com_help_info


def _light_enumerate_attack(argv, ip, port, attack_mode, libc_path=None, loop_time=0x10, loop_list:List[List]=None):
    def wrapper1(func_call):
        @functools.wraps(func_call)
        def wrapper2(*args, **kwargs):
                # check 
                _check_func_args(func_call, loop_list, True)
                io, _ = args
                io.close()
                # auto detect libc_path
                if argv is not None and libc_path is None:
                    _libc_path = ldd_get_libc_path(argv)
                else:
                    _libc_path = libc_path
                # process or remote
                if attack_mode == _EnumerateAttackMode.LOCAL:
                    _attack_local(argv, _libc_path, func_call, loop_time, loop_list)
                elif attack_mode == _EnumerateAttackMode.REMOTE:
                    _attack_remote(_libc_path, ip, port, func_call, loop_time, loop_list)
        return wrapper2
    return wrapper1


local_enumerate_attack = functools.partial(_light_enumerate_attack, ip=None, port=None, attack_mode=_EnumerateAttackMode.LOCAL)

remote_enumerate_attack = functools.partial(_light_enumerate_attack, argv=None, attack_mode=_EnumerateAttackMode.REMOTE)

"""
For example, if you use 'local_enumerate_attack', firstly, define your attack_func:

def attack_func(p:tube, libc:ELF, l1, l2):
    # ......
    if success:
        raise PwncliExit()
    else:
        raise RuntimeError()
    pass

then, use the decorator:

@local_enumerate_attack(argv="xxx.elf", libc_path="xxx.so", loop_time=1,loop_list=[[t11, t12, t13], [t21, t22]])
def attack_func(p:tube, libc:ELF, t1, t2):
    # ......
    if success:
        raise PwncliExit()
    else:
        raise RuntimeError()
    pass

and will exec:
    attack_func(process(argc), ELF(libc_path), t11, t21)
    attack_func(process(argc), ELF(libc_path), t12, t22)
    attack_func(process(argc), ELF(libc_path), t13, t21)
    attack_func(process(argc), ELF(libc_path), t21, t22)
    attack_func(process(argc), ELF(libc_path), t22, t21)
    attack_func(process(argc), ELF(libc_path), t22, t22)

or you use:
@local_enumerate_attack(argv="xxx.elf", libc_path="xxx.so", loop_time=20, loop_list=None)
def attack_func(p:tube, libc:ELF):
    # ......
    if success:
        raise PwncliExit()
    else:
        raise RuntimeError()
    pass

and will exec:
    for i in range(20):
        attack_func(process(argc), ELF(libc_path))
"""