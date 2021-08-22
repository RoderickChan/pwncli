import functools
import time
import os
from enum import Enum, unique
from pwn import remote, process, ELF, tube
from inspect import signature, _empty
from pwncli.utils.exceptions import PwncliExit

__all__  = ['time_count', 'SleepMode', 'sleep_call', "local_enumerate_attack", "remote_enumerate_attack"]


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
class SleepMode(Enum):
    BEFORE = 1
    AFTER = 2
    ALL = 3


def sleep_call(second: int = 1, mod: SleepMode = SleepMode.BEFORE):
    """Sleep before and after call function

    Args:
        second (int, optional): Sleep time. Defaults to 1.
        mod (SleepMode, optional): Sleep mode. Defaults to SleepMode.BEFORE.
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


@unique
class _EnumerateAttackMode(Enum):
    LOCAL=0
    REMOTE=1


def _attack_local(argv, libc_path, call_func, loop_time):
    # check para
    if argv is None or (not os.path.isfile(libc_path)) or loop_time <= 0 or call_func is None:
        raise RuntimeError("Para error! argv:{} libc_path:{} loop_time: {} call_func: {}".format(argv, libc_path, loop_time, call_func.__name__))
    libc = ELF(libc_path)
    while loop_time > 0:
        loop_time -= 1
        p = process(argv)
        libc.address = 0
        try:
            call_func(p, libc)
        except PwncliExit as ex:
            print("Pwncli is exiting...", ex)
            break
        except:
            p.close()


def _attack_remote(libc_path, ip, port, call_func, loop_time):
    if ip is None or port is None or (not os.path.isfile(libc_path)) or loop_time <= 0 or call_func is None:
        raise RuntimeError("Para error! is:{} port: {} libc_path:{} loop_time: {} call_func: {}".format(ip, port, libc_path, loop_time, call_func.__name__))
    libc = ELF(libc_path)
    while loop_time > 0:
        loop_time -= 1
        p = remote(ip, port)
        libc.address = 0
        try:
            call_func(p, libc)
        except PwncliExit as ex:
            print("Pwncli is exiting...", ex)
            break
        except:
            p.close()


def _light_enumerate_attack(argv, libc_path, ip, port, loop_time, attack_mode):
    def wrapper1(func_call):
        @functools.wraps(func_call)
        def wrapper2(*args, **kwargs):
            # check func_paras
                sig = signature(func_call)
                pars = sig.parameters
                com_help_info = "\n\t\t\tThe first para must be 'tube' type, the second one must be 'ELF' type for libc!"
                if len(pars) != 2:
                    raise RuntimeError("  Length of para must be 2.\n"+com_help_info)
                
                kl = []
                vl = []
                for k, v in pars.items():
                    kl.append(k)
                    vl.append(v)
                    if v.annotation == _empty:
                        raise RuntimeError("  Please add annotation for you attack-func's parameters, which can help me check para-type!"+com_help_info)

                is_right = (issubclass(vl[0].annotation, tube)) and (issubclass(vl[1].annotation, ELF))
                if not is_right:
                    raise RuntimeError("  Type of {} is: {}, type of {} is {}.".format(
                        kl[0], vl[0].annotation, kl[1], vl[1].annotation
                    )+com_help_info)

                # process or remote
                if attack_mode == _EnumerateAttackMode.LOCAL:
                    _attack_local(argv, libc_path, func_call, loop_time)
                elif attack_mode == _EnumerateAttackMode.REMOTE:
                    _attack_remote(libc_path, ip, port, func_call, loop_time)
        
        return wrapper2
    return wrapper1


local_enumerate_attack = functools.partial(_light_enumerate_attack, ip=None, port=None, attack_mode=_EnumerateAttackMode.LOCAL)

remote_enumerate_attack = functools.partial(_light_enumerate_attack, argv=None, attack_mode=_EnumerateAttackMode.REMOTE)
