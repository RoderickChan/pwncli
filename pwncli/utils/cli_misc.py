
from pwncli.cli import _treasure, gift
from pwncli.cli import Environment as _ctx
from pwncli.utils.misc import get_callframe_info


__all__ = ['stop']

def stop():
    """
    stop the program and print the caller's info
    :return:
    """
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
    if gift.get('io', None):
        pid = gift['io'].proc.pid

    msg = '[*] stop'
    if lineno != -1:
        msg += ' at module: {}  function: {}  line: {}'.format(module_name, func_name, lineno)
    if pid != -1:
        msg += '  local pid: {}'.format(pid)
    _ctx._log2(msg)
    input()
