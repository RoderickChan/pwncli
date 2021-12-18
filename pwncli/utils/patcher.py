#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : patcher.py
@Time    : 2021/12/05 22:12:49
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : Patcher for ELF file, based on lief from https://github.com/lief-project/LIEF
'''

import os
import lief
from typing import List

class Patcher:
    def __init__(self, filepath: str) -> None:
        if not os.path.isfile(filepath):
            raise FileExistsError("{} doesn't exists!".format(filepath))
        self._filepath = filepath
        self._binary = lief.parse(filepath)
    
    
    def get_content_from_virtual_address(self, va: int, size: int) -> List[int]:
        return self._binary.get_content_from_virtual_address(va, size)


    def patch_address(self, va: int, content: List[int]):
        self._binary.patch_address(va, content)


    def save(self, filepath: str=None):
        if filepath is None:
            filepath = self._filepath
        self._binary.write(filepath)

    
def patch_file_xor(filepath: str, xor_key: int, va: int, size: int, output: str=None):
    assert xor_key > 0 and xor_key < 0x100, "xor key error!"
    if output is None:
        output = filepath
    p = Patcher(filepath)
    ori = p.get_content_from_virtual_address(va, size)
    xor_val = [x ^ xor_key for x in ori]
    p.patch_address(va, xor_val)
    p.save(output)