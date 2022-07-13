#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : libcbox.py
@Time    : 2021/11/23 23:46:27
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : Find libc by web api from https://github.com/niklasb/libc-database/tree/master/searchengine
'''


import re
import shutil
import tempfile
from time import sleep
import requests
import json
import threading
import os
from .misc import errlog_exit, log_ex, one_gadget
from .ropperbox import RopperBox

__all__ = ["LibcBox"]

class LibcBox:
    def __init__(self, debug=False):
        self._data = dict() # post data, is a dict
        self._res = None # post res, is a dict
        self._symbols = None
        self._call_searcher = False
        self._downloaded = False

        self.debug = debug # open debug or not

        self._rb = None # RopperBox
        self._tmp_dir = tempfile.mkdtemp()

        self._lock = threading.Lock()

    def __del__(self):
        self.__clean()
  

    def _log(self, *args, **kwargs):
        if self.debug:
            log_ex(*args, **kwargs)


    def __clean(self):
        if self._tmp_dir and os.path.exists(self._tmp_dir):
            shutil.rmtree(self._tmp_dir)
            self._log("delete tmp directory {} success!".format(self._tmp_dir))

    def __time_count(self, n, to_exit=True):
        if n <= 0:
             n = 30

        while n:
            if self._downloaded:
                break
            sleep(1)
            n -= 1
        
        if to_exit:
            errlog_exit("Download work donnot finish in {}s".format(n))


    def __post_to_find(self):
        r = requests.post(url="https://libc.rip/api/find", data=json.dumps(self._data), headers={'Content-Type': 'application/json'})
        if r.status_code != 200:
            errlog_exit("Error status_code: {}".format(r.status_code))
        self._res = json.loads(r.text)
    

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
    
    def __show_result(self, version_start):
        _pattern = "libc?6?[-_](\d\.\d\d)"
        options = []
        print("="*90)
        print("There are candidates with glibc version >= {}: ".format(version_start))
        for i, r in enumerate(self._res):
            _match = re.search(_pattern, r['id'])
            if _match and _match.groups()[0] < version_start:
                continue
            print(
"""[{}] ==> version: {}
        buildid: {}
        sha256 : {}
        symbols: {}
""".format(i+1, r['id'], r['buildid'], r['sha256'], r['symbols']))
            options.append(i+1)
        print("="*90)
        return options

    
    def __download_resources(self, key, mode, redownload):
        url = self._res[key]
        fn = os.path.join(self._tmp_dir, url.split("/")[-1])
        if os.path.exists(fn) and (not redownload):
            self._log("{} exists in current directory, it would not be downloaded again!".format(fn))
            return
        
        self._log("start to download {}...".format(key))
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


    def __download_async(self, download_symbols, download_so, download_deb, redownload, load_gadgets):
        if self._lock.acquire():
            self._lock.locked()
        
        if not self._downloaded or redownload:
            t1 = threading.Thread(target=self.__download_resources, args=('symbols_url', 't', redownload))
            t1.start()
            t2 = threading.Thread(target=self.__download_resources, args=('download_url', 'b', redownload))
            t2.start()
            t3 = threading.Thread(target=self.__download_resources, args=('libs_url', 'b', redownload))
            t3.start()
            t1.join()
            t2.join()
            t3.join()
            self._downloaded = True

        if download_symbols:
            name = self._res['symbols_url'].split("/")[-1]
            fn   = os.path.join(self._tmp_dir, name)
            shutil.copyfile(fn, name)
            self._log("Download {} success!".format(name))
            if os.path.exists(fn):
                with open(fn, "r", encoding="utf-8") as f:
                    self._symbols = f.read()

        if download_so:
            name = self._res['download_url'].split("/")[-1]
            fn   = os.path.join(self._tmp_dir, name)
            shutil.copyfile(fn, name)
            self._log("Download {} success!".format(name))

        if download_deb:
            name = self._res['libs_url'].split("/")[-1]
            fn   = os.path.join(self._tmp_dir, name)
            shutil.copyfile(fn, name)
            self._log("Download {} success!".format(name))

        if load_gadgets:
            self._log("start to load gadget...")
            threading.Thread(target=self.get_ropperbox, args=(False,), daemon=True).start()
        
        self._lock.release()


    def reset(self):
        self._data = dict() # post data, is a dict
        self._res = None # post res, is a dict
        self._symbols = None
        self._call_searcher = False
        self._downloaded = False

        self._rb = None
        if self._tmp_dir and os.path.exists(self._tmp_dir):
            shutil.rmtree(self._tmp_dir)
        self._tmp_dir = tempfile.mkdtemp()
        self._log("reset success!")


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

    
    def search(self, *, download_symbols=False, download_so=False, download_deb=False, redownload=False, version_start="2.23", load_gadgets=False):
        if not self._data:
            errlog_exit("No condition! Please add condition first!")
        if version_start and not re.search("^\d\.\d\d$", version_start):
            errlog_exit("Invalid version_start!")
        self.__post_to_find()
        if not self._res:
            errlog_exit("Cannot find a libc file to meet your expectaions, please check your conditions!")

        options = self.__show_result(version_start)
        if len(self._res) > 1:
            while 1:
                ans = input("please choose one number or 'q' to quit: ")
                if ans[:-1] == "q" or ans[:-1] == "quit":
                    print("quit libcbox!")
                    exit(-1)
                ans = int(ans)
                if ans in options:
                    self._res = self._res[ans - 1]
                    break
                print("Wrong input!")
        else:
            self._res = self._res[0]
        
        threading.Thread(target=self.__download_async, args=(download_symbols, download_so, download_deb, redownload, load_gadgets), daemon=True).start()
        self._call_searcher = True
        
    
    def dump(self, symbol_name:str, show: bool=True) -> int:
        if not self._call_searcher:
            errlog_exit("Please call search before you dump!")
        if symbol_name in self._res['symbols']:
            res = self._res['symbols'][symbol_name]
            res = int(res, base=16)
            if show:
                log_ex("%s address ==> %s", symbol_name, hex(res))
            return res
        else:
            self.__time_count(10, False)
            if not self._symbols:
                self._symbols = requests.get(self._res['symbols_url']).text
            
            for line in self._symbols.splitlines(False):
                name, adr = line.split()
                if name == symbol_name:
                    res = int(adr, base=16)
                    if show:
                        log_ex("%s address ==> %s", symbol_name, hex(res))
                    return res
        
        errlog_exit("Cannot find symbol: {}".format(symbol_name))


    def dump_str_bin_sh(self):
        return self.dump("str_bin_sh")


    def dump_one_gadget(self, libc_base: int, more: bool=False, show=True) -> list:
        if not self._call_searcher:
            errlog_exit("Please call search before you dump!")
        self.__time_count(30)
        res = [libc_base + x  for x in one_gadget(condition=self._res['buildid'], more=more, buildid=True)]
        if show:
            log_ex("one_gadget: %r", [hex(x) for x in res])
        return res


    def get_ropperbox(self, debug=False) -> RopperBox:
        if not self._rb:
            if not self._call_searcher:
                errlog_exit("Please call search before you get_ropperbox!")
            self.__time_count(30)
            name = self._res['download_url'].split("/")[-1]
            fn   = os.path.join(self._tmp_dir, name)
            self._rb = RopperBox(debug=debug)
            self._rb.add_file("libc", fn, None)
        
        return self._rb

