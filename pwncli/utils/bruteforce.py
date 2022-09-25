#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : bruteforce.py
@Time    : 2021/11/23 23:48:49
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : bruteforce methods
'''



from pwnlib.util.hashes import *
from pwnlib.util.iters import bruteforce, mbruteforce
from .misc import errlog_exit
from string import printable
import typing

__all__ = [
    "bruteforce_hash_prefixstr",
    "mbruteforce_hash_prefixstr"
]

_hash_algos = (
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512"
)

#--------------------hash related----------------------
def __inner_bruteforce(hash_algo:str, prefix_str:str, check_res_func:typing.Callable, 
        alphabet:str, start_length:int, max_length:int, multithread):
    assert max_length >= start_length
    assert isinstance(prefix_str, str)
    assert isinstance(alphabet, str)

    if hash_algo not in _hash_algos:
        errlog_exit("Hash algo error, only support for: {}".format(_hash_algos))

    def func(s):
        hash_func = globals()[hash_algo+"sumhex"]
        res = hash_func((prefix_str+s).encode())
        return check_res_func(res)
    
    res = None
    for length in range(start_length, max_length+1):
        _use_func = mbruteforce if multithread else bruteforce
        res = _use_func(func, alphabet, length, method='fixed')
        if res:
            break
    return res


def bruteforce_hash_prefixstr(hash_algo:str, prefix_str:str, check_res_func:typing.Callable, 
        alphabet:str=printable.strip(), start_length:int=4, max_length=6):
    """Bruteforce hash value when prefix string is given, like sha256('eRt<'+?) starts with 000000

    Args:
        hash_algo (str): hash algorithm name: [md5, sha1, sha224, sha256, sha384, sha512].
        prefix_str (str): Prefix string.
        check_res_func (typing.Callable): func to check hash value, like: lambda x: x.startswith('000000').
        alphabet (str, optional): String used. Defaults to printable.strip().
        start_length (int, optional): Starting length. Defaults to 4.
        max_length (int, optional): Max length. Defaults to 6.

    Returns:
        str: if not find, return None.

    Example:
        >>> res = bruteforce_hash_prefixstr("sha256", "eRt<", lambda x: x.startswith("0000"), max_length=4)
        >>> res
        '02)T'
        >>> sha256sumhex(("eRt<"+res).encode()).startswith("0000")
        True
    """
    return __inner_bruteforce(hash_algo, prefix_str, check_res_func, alphabet, start_length, max_length, False)


def mbruteforce_hash_prefixstr(hash_algo:str, prefix_str:str, check_res_func:typing.Callable, 
        alphabet:str=printable.strip(), start_length:int=4, max_length=6):
    """Bruteforce hash value when prefix string is given, like sha256('eRt<'+?) starts with 000000

    Args:
        hash_algo (str): hash algorithm name: [md5, sha1, sha224, sha256, sha384, sha512].
        prefix_str (str): Prefix string.
        check_res_func (typing.Callable): func to check hash value, like: lambda x: x.startswith('000000').
        alphabet (str, optional): String used. Defaults to printable.strip().
        start_length (int, optional): Starting length. Defaults to 4.
        max_length (int, optional): Max length. Defaults to 6.

    Returns:
        str: if not find, return None.
    
    Example:
        >>> res = mbruteforce_hash_prefixstr("sha256", "eRt<", lambda x: x.startswith("000000"), max_length=6)
        >>> res
        '0_TR'
        >>> sha256sumhex(("eRt<"+res).encode()).startswith("000000")
        True
    """
    return __inner_bruteforce(hash_algo, prefix_str, check_res_func, alphabet, start_length, max_length, True)

    
if __name__ == "__main__":
    import doctest
    doctest.testmod(verbose=True)