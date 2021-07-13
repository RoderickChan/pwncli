import functools
import time
from enum import Enum, unique

__all__  = ['time_count', 'SleepMode', 'sleep_call']


def time_count(func):
    """
    A decorate: count the time used by function
    :param func:
    :return:
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
    """
    A decorate: sleep before and after call function
    :param second: sleep seconds
    :param mod: sleep mode
    :return:
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

