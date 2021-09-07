import functools
import time
import os
from enum import Enum, unique
from pwn import remote, process, ELF, tube
from inspect import signature, _empty
from pwncli.utils.exceptions import PwncliExit
from typing import List
from itertools import product

__all__  = ['time_count', 'sleep_call_before', "sleep_call_after", "sleep_call_all", "local_enumerate_attack", "remote_enumerate_attack"]


def time_count(func):
    """Count the time consuming of a function

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


def _call_func_invoke(p:tube, libc:ELF, loop_list):
    if loop_list:
        for iter_items in product(*loop_list):
            try:
                print("call func: {}, loop-args: {}".format(call_func.__name__, iter_items))
                call_func(p, libc, *iter_items)
            except PwncliExit as ex:
                print("Pwncli is exiting...", ex)
                return True
            except:
                p.close()
    else:
        try:
            print("call func: {}".format(call_func.__name__))
            call_func(p, libc)
        except PwncliExit as ex:
            print("Pwncli is exiting...", ex)
            return True
        except:
            p.close()
    return False


def _attack_local(argv, libc_path, call_func, loop_time, loop_list):
    # check para
    if argv is None or (not os.path.isfile(libc_path)) or loop_time <= 0 or call_func is None:
        raise RuntimeError("Para error! argv:{} libc_path:{} loop_time: {} call_func: {}".format(argv, libc_path, loop_time, call_func.__name__))
    libc = ELF(libc_path)
    while loop_time > 0:
        loop_time -= 1
        p = process(argv)
        libc.address = 0
        if _call_func_invoke(p, libc, loop_list):
            break


def _attack_remote(libc_path, ip, port, call_func, loop_time, loop_list):
    if ip is None or port is None or (not os.path.isfile(libc_path)) or loop_time <= 0 or call_func is None:
        raise RuntimeError("Para error! is:{} port: {} libc_path:{} loop_time: {} call_func: {}".format(ip, port, libc_path, loop_time, call_func.__name__))
    libc = ELF(libc_path)
    while loop_time > 0:
        loop_time -= 1
        p = remote(ip, port)
        libc.address = 0
        if _call_func_invoke(p, libc, loop_list):
            break


def _check_func_args(func_call, loop_list):
    assert func_call is not None and callable(func_call), "func_call {} error!".format(func_call)
    # check func_paras
    sig = signature(func_call)
    pars = sig.parameters
    com_help_info = "\n\t\t\tThe first para must be 'tube' type, the second one must be 'ELF' type for libc! If loop_list is specified, every element is a list or tuple."
    # if have looplist, the length of func must be 2 + len(loop_list[0])
    if loop_list:
        assert isinstance(loop_list, (tuple, list)), "  Loop_list is not tuple or list.\n"+com_help_info
        assert len(loop_list) > 0, "  Length of loop_list is 0.\n"+com_help_info
        for ll in loop_list:
            assert isinstance(ll, (tuple, list)), "  An element of loop_list is not tuple or list.\n"+com_help_info
            assert len(ll) > 0, "  Length of an element of loop_list is 0.\n"+com_help_info
        # check paras len
        assert len(pars) == (2 + len(loop_list)), "  Length of para is not {}.\n".format(2 + len(loop_list))+com_help_info
    else:
        assert len(pars) == 2, "  Length of para is not 2.\n"+com_help_info
    
    kl = []
    vl = []
    for k, v in pars.items():
        kl.append(k)
        vl.append(v)
    
    assert (issubclass(vl[0].annotation, tube)) and (issubclass(vl[1].annotation, ELF)), "  Type of {} is: {}, type of {} is {}.".format(kl[0], 
        vl[0].annotation, kl[1], vl[1].annotation)+com_help_info


def _light_enumerate_attack(argv, libc_path, ip, port, loop_time, attack_mode, loop_list:List[List]):
    def wrapper1(func_call):
        @functools.wraps(func_call)
        def wrapper2(*args, **kwargs):
                _check_func_args(func_call, loop_list)
                if loop_list: # use loop_list instead of loop_time
                    loop_time = 1
                # process or remote
                if attack_mode == _EnumerateAttackMode.LOCAL:
                    _attack_local(argv, libc_path, func_call, loop_time, loop_list)
                elif attack_mode == _EnumerateAttackMode.REMOTE:
                    _attack_remote(libc_path, ip, port, func_call, loop_time, loop_list)
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