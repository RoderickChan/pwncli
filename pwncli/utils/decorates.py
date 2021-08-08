import functools
import time
from enum import Enum, unique

__all__  = ['time_count', 'SleepMode', 'sleep_call']


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

