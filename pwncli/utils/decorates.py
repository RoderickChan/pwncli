#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : decorates.py
@Time    : 2021/11/23 23:48:12
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : Decorators
'''


import functools
import time
import os
import signal
from enum import Enum, unique
from pwn import remote, process, ELF, tube, context
try:
    from collections.abc import Iterable
except:
    from collections import Iterable

from inspect import signature
from .exceptions import PwncliExit
from typing import List
from itertools import product
from .misc import log_ex, warn_ex_highlight, ldd_get_libc_path, errlog_exit

__all__  = [
    'smart_decorator', 
    'time_count', 
    'sleep_call_before', 
    "sleep_call_after", 
    "sleep_call_all", 
    "local_enumerate_attack", 
    "remote_enumerate_attack",
    "smart_enumerate_attack",
    "stopwatch",
    "deprecated", 
    "unused",
    "show_name",
    "always_success",
    "only_debug",
    "only_remote",
    "call_limit"
    ]


def always_success(show_err=False):
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
    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            warn_ex_highlight("This function: {} is deprecated. {}".format(func.__name__, msg))
            res = func(*args, **kwargs)
            return res
        return wrapper2
    return wrapper1


def unused(msg: str=""):
    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            warn_ex_highlight("This function: {} is unused and it would be removed in later version. {}".format(func.__name__, msg))
            return None
        return wrapper2
    return wrapper1

def call_limit(times: int=1, warn_=True):
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

def smart_decorator(decorator):
    """Make a function to be a decorator.

    Args:
        decorator (Callable): Callable object.
    """
    def wrapper1(func=None, *args, **kwargs):
        if func is not None:
            return decorator(func=func, *args, **kwargs)
        def wrapper2(func):
            return decorator(func=func, *args, **kwargs)
        return wrapper2
    return wrapper1


def show_name(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        args_str = ""
        kwargs_str = ""
        if args:
            args_str = ", ".join(str(x) for x in args)
        if kwargs:
            if args_str:
                args_str += ", "
            kwargs_str = ", ".join("{}={}".format(_k, _v) for _k, _v in kwargs.items())
        log_ex("call func: {}({}{})".format(func.__name__, args_str, kwargs_str))
        res = func(*args, **kwargs)
        return res
    return wrapper


def time_count(func):
    """Count the time-consuming of a function

    Args:
        func ([type]): Func

    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        print('=' * 50)
        print('function #{}# start...'.format(func.__name__))
        start = time.time()
        res = func(*args, **kwargs)
        end = time.time()
        print('function #{}# end...execute time: {} s | {} min'.format(func.__name__, end - start, (end - start) / 60))
        return res
    return wrapper


def stopwatch(seconds, callback=None):
    """
    seconds: seconds to raise TimeoutError when timeout
    callback: callback when timeout
    """
    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            def handler(n, f):
                raise TimeoutError()
            signal.signal(signal.SIGALRM, handler)
            signal.alarm(seconds)
            try:
                res = func(*args, **kwargs)
                signal.alarm(0)
            except TimeoutError:
                res = None
                if callback:
                    res = callback()
                else:
                    errlog_exit("Timeout!")
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
                pass
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

from pwncli.cli import gift
from .cli_misc import copy_current_io, get_current_codebase_addr, get_current_libcbase_addr


# only call when gift.remote is True
def only_debug(show_warn=True):
    def wrapper1(func_call):
        @functools.wraps(func_call)
        def wrapper2(*args, **kwargs):
            if gift.debug and not gift.remote and gift.io:
                res = func_call(*args, **kwargs)
            else:
                if show_warn:
                    warn_ex_highlight("{} will not be called because gift.debug is not True.".format(func_call.__name__))
                res = None
            return res
        return wrapper2
    return wrapper1


# only call when gift.remote is True
def only_remote(show_warn=True):
    def wrapper1(func_call):
        @functools.wraps(func_call)
        def wrapper2(*args, **kwargs):
            if gift.remote and not gift.debug and gift.io:
                res = func_call(*args, **kwargs)
            else:
                if show_warn:
                    warn_ex_highlight("{} will not be called because gift.remote is not True.".format(func_call.__name__))
                res = None
            return res
        return wrapper2
    return wrapper1


def _smart_enumerate_attack_helper2():
    _cof = 10
    while _cof:
        try:
            # copy io
            gift.io = copy_current_io()
            _cof = 0
        except KeyboardInterrupt:
            errlog_exit("KeyboardInterrupt!")
        except:
            _cof -= 1

    if gift.debug:
        if gift["_elf_base"] is not None:
            gift._elf_base = gift.elf.address or get_current_codebase_addr
        if gift.elf.pie: # must have elf when debug
            gift['elf'].address = 0
        if not gift['elf'].statically_linked:
            rp = None
            if gift.process_env and "LD_PRELOAD" in gift.process_env:
                for rp_ in gift.process_env["LD_PRELOAD"].split(";"):
                    if "libc" in rp_:
                        rp = rp_
                        break

            if not rp:
                rp = ldd_get_libc_path(context.binary.path)

            if rp:
                gift['libc'].address = 0
                if gift["_libc_base"] is not None:
                    gift['_libc_base'] = get_current_libcbase_addr()
            else:
                if gift["_libc_base"] is not None:
                    gift['libc'] = gift['io'].libc
                    gift['_libc_base'] = gift['libc'].address
                gift['libc'].address = 0

    elif gift.remote:
        if gift.libc:
            gift['libc'].address = 0
        if gift.elf and gift.elf.pie:
            gift['elf'].address = 0

def _smart_enumerate_attack_helper(func_call, loop_time, loop_list, show_error):
    # close current io
    gift.io.close()
    if loop_list:
        l_count = 0
        for iter_items in product(*loop_list):
            l_count += 1
            _smart_enumerate_attack_helper2()
            log_ex("[{}] ===> call func: {}, func_args: {}".format(l_count, func_call.__name__, iter_items))
            try:
                func_call(*iter_items)
            except PwncliExit as ex:
                log_ex("Pwncli is exiting...ex info: {}".format(ex))
                break
            except KeyboardInterrupt:
                errlog_exit("KeyboardInterrupt!")
                pass
            except Exception as e:
                if show_error:
                    log_ex("error: %r", e)
                pass
            finally:
                try:
                    gift.io.close()
                except:
                    pass
            
    else:
        for i in range(loop_time):
            _smart_enumerate_attack_helper2()
            log_ex("[{}] ===> call func: {}".format(i + 1, func_call.__name__))
            try:
                func_call()
            except PwncliExit as ex:
                log_ex("Pwncli is exiting...ex info: {}".format(ex))
                break
            except KeyboardInterrupt:
                errlog_exit("KeyboardInterrupt!")
                pass
            except Exception as e:
                if show_error:
                    log_ex("error: %r", e)
                pass
            finally:
                try:
                    gift.io.close()
                except:
                    pass
            

def smart_enumerate_attack(loop_time: int=0x10, loop_list:List[List]=None, show_error=False):
    def wrapper1(func_call):
        @functools.wraps(func_call)
        def wrapper2(*args, **kwargs):
            _check_func_args(func_call, loop_list, False)
            if gift.from_script:
                _smart_enumerate_attack_helper(func_call, loop_time, loop_list, show_error)
            else:
                errlog_exit("'smart_enumerate_attack' only support script mode!")
        return wrapper2
    return wrapper1

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