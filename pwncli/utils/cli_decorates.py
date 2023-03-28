#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : cli_decorates.py
@Time    : 2023/03/28 13:00:56
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : cli_decorator
'''

import functools
from itertools import product
from typing import List

from pwn import context

from ..cli import gift
from .cli_misc import (copy_current_io, get_current_codebase_addr,
                       get_current_libcbase_addr)
from .decorates import _check_func_args
from .exceptions import PwncliExit
from .misc import errlog_exit, ldd_get_libc_path, log_ex

__all__ = [
    "smart_enumerate_attack"
]

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
            gift._elf_base = gift.elf.address or get_current_codebase_addr()
        if gift.elf.pie:  # must have elf when debug
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
            log_ex("[{}] ===> call func: {}, func_args: {}".format(
                l_count, func_call.__name__, iter_items))
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


def smart_enumerate_attack(loop_time: int = 0x10, loop_list: List[List] = None, show_error=False):
    def wrapper1(func_call):
        @functools.wraps(func_call)
        def wrapper2(*args, **kwargs):
            _check_func_args(func_call, loop_list, False)
            if gift.from_script:
                _smart_enumerate_attack_helper(
                    func_call, loop_time, loop_list, show_error)
            else:
                errlog_exit(
                    "'smart_enumerate_attack' only support script mode!")
        return wrapper2
    return wrapper1
