#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : libcbox.py
@Time    : 2021/11/23 23:46:27
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : Find libc by web api from https://github.com/niklasb/libc-database/tree/master/searchengine
'''


import requests
import json
import threading
import os
from tempfile import TemporaryFile
from pwncli.utils.misc import errlog_exit, log2_ex

__all__ = ["LibcBox"]

class LibcBox:
    def __init__(self):
        self._data = {} # post data, is a dict
        self._res = None # post res, is a dict
        self._symbols = None
        self._call_searcher = False

    def __post_to_find(self):
        r = requests.post(url="https://libc.rip/api/find", data=json.dumps(self._data), headers={'Content-Type': 'application/json'})
        if r.status_code != 200:
            errlog_exit("Error status_code: {}".format(r.status_code))
        self._res = json.loads(r.text)
        # print(self._res)
    

    def __process_symbols(self, data:dict):
        if "symbols" not in self._data:
            self._data['symbols'] = data
        else:
            cur_symbols = self._data['symbols']
            for k, v in data.items():
                if k in cur_symbols and v != cur_symbols[k]:
                    errlog_exit("{} exists and you add two different values for symbol '{}'. First value: {} second value: {}.".format(k, k, cur_symbols[k], v))
                cur_symbols[k] = v
        
    def __process_hash(self, hash_type, hash_value):
        if isinstance(hash_value, int):
            hash_value = hex(hash_value)[2:]
        elif isinstance(hash_value, str):
            if hash_value.startswith("0x"):
                hash_value = hash_value[2:]
        else:
            errlog_exit("Wrong hash_value: {}, must be int or hex-str!".format(hash_value))

        if hash_type in self._data and hash_value != self._data[hash_type]:
            errlog_exit("{} exists and you add two different values for '{}'. First value: {} second value: {}.".format(hash_type, hash_type, self._data[hash_type], hash_value))
        self._data[hash_type] = hash_value
    
    def __show_result(self):
        print("="*90)
        print("There are {} candidates: ".format(len(self._res)))
        for i, r in enumerate(self._res):
            print(
"""[{}] ==> version: {}
        buildid: {}
        sha256 : {}
        symbols: {}
""".format(i+1, r['id'], r['buildid'], r['sha256'], r['symbols']))
        print("="*90)
        pass

    
    def __download_resources(self, key, mode, redownload):
        url = self._res[key]
        fn = url.split("/")[-1]
        if os.path.exists(fn) and (not redownload):
            log2_ex("{} exists in current directory, it will not be downloaded again!".format(fn))
            return
        if mode == "t":
            r = requests.get(url)
            with open(fn, "w", encoding='utf-8') as f:
                f.write(r.text)
        elif mode == 'b':
            r = requests.get(url, stream=True)
            with open(fn, "wb") as f:
                for chunk in r.iter_content(4096):
                    if chunk:
                        f.write(chunk)
        log2_ex("Download {} success!".format(fn))


    def add_symbol(self, symbol_name:str, address:int):
        self.__process_symbols({symbol_name:hex(address)})
        return self

    def add_md5(self, hash_val):
        self.__process_hash('md5', hash_val)
        return self

    def add_sha1(self, hash_val):
        self.__process_hash('sha1', hash_val)
        return self

    def add_sha256(self, hash_val):
        self.__process_hash('sha256', hash_val)
        return self

    def add_buildid(self, buildid):
        self.__process_hash('buildid', buildid)
        return self

    
    def search(self, *, download_symbols=False, download_so=False, download_libs=False, redownload=False):
        if not self._data:
            errlog_exit("No condition! Please add condition first!")
        self.__post_to_find()
        if not self._res:
            errlog_exit("Cannot find a libc file to meet your expectaions, please check your conditions!")

        self.__show_result()
        if len(self._res) > 1:
            while 1:
                ans = input("please choose one number or 'q' to quit: ")
                if ans[:-1] == "q" or ans[:-1] == "quit":
                    print("quit libcbox!")
                    exit(-1)
                ans = int(ans)
                if ans > 0 and ans < len(self._res) + 1:
                    self._res = self._res[ans - 1]
                    break
                print("Wrong input!")
        else:
            self._res = self._res[0]
        
        if download_symbols:
            t = threading.Thread(target=self.__download_resources, args=('symbols_url', 't', redownload))
            t.start()
            fn = self._res['symbols_url'].split("/")[-1]
            if os.path.exists(fn):
                with open(fn, "r", encoding="utf-8") as f:
                    self._symbols = f.read()

        if download_so:
            t = threading.Thread(target=self.__download_resources, args=('download_url', 'b', redownload))
            t.start()

        if download_libs:
            t = threading.Thread(target=self.__download_resources, args=('libs_url', 'b', redownload))
            t.start()

        self._call_searcher = True
        
    
    def dump(self, symbol_name:str) -> int:
        if not self._call_searcher:
            errlog_exit("Please call search before you dump!")
        if symbol_name in ('dup2', 'printf', 'puts', 'str_bin_sh', 'read', 'strcpy', 'system', 'write', '__libc_start_main_ret'):
            res = self._res['symbols'][symbol_name]
            return int(res, base=16)
        else:
            if not self._symbols:
                self._symbols = requests.get(self._res['symbols_url']).text
            
            for line in self._symbols.splitlines(False):
                name, adr = line.split()
                if name == symbol_name:
                    return int(adr, base=16)
        
        errlog_exit("Cannot find symbol: {}".format(symbol_name))


