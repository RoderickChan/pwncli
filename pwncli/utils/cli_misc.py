
import os
from pwncli.cli import _treasure, gift
from pwncli.utils.misc import get_callframe_info, log2_ex, errlog_exit,one_gadget_binary, get_segment_base_addr_by_proc_maps


def stop(enable=True):
    """Stop the program and print the caller's info

    Args:
        enable (bool, optional): if it's False, this function will return directly. Defaults to True.
    """
    if not enable:
        return

    if _treasure.get('no_stop', None):
        return

    func_name = ''
    module_name = ''
    lineno, pid = -1, -1
    try:
        # try to get file line number
        module_name, func_name, lineno = get_callframe_info(depth=3)
    except:
        lineno = -1

    # try to get pid
    if gift.get('io', None) and gift.get('debug', None):
        pid = gift['io'].proc.pid

    msg = 'Stop'
    if lineno != -1:
        msg += ' at module: {}  function: {}  line: {}'.format(module_name, func_name, lineno)
    if pid != -1:
        msg += '  local pid: {}'.format(pid)
    log2_ex(msg)
    input(" Press any key to continue......")


#----------------------------useful function-------------------------
def get_current_one_gadget(more=False):
    """Get current filename's all one_gadget.

    """
    if not gift.get('filename', None):
        errlog_exit("Cannot get_current_one_gadget, filename is None!")
    return one_gadget_binary(gift['filename'], more)

_cache_segment_base_addr = None
def __get_current_segment_base_addr(use_cache=True) -> dict:
    global _cache_segment_base_addr
    """Get current process's segments' base address."""
    if use_cache and _cache_segment_base_addr is not None:
        return _cache_segment_base_addr
    # try to get pid
    if gift.get('io', None) and gift.get('debug', None):
        pid = gift['io'].proc.pid
        filename = gift.get('filename', None)
        if filename is not None:
            filename = os.path.split(os.path.abspath(filename))[1]
        _cache_segment_base_addr = get_segment_base_addr_by_proc_maps(pid, filename)
        return _cache_segment_base_addr
    else:
        errlog_exit("get_current_segment_base_addr failed! No pid!")


def get_current_codebase_addr(use_cache=True) -> int:
    r = __get_current_segment_base_addr(use_cache)
    return r['code']


def get_current_libcbase_addr(use_cache=True) -> int:
    r = __get_current_segment_base_addr(use_cache)
    return r['libc']


def get_current_stackbase_addr(use_cache=True) -> int:
    r = __get_current_segment_base_addr(use_cache)
    return r['stack']


def get_current_heapbase_addr(use_cache=True) -> int:
    r = __get_current_segment_base_addr(use_cache)
    return r['heap']