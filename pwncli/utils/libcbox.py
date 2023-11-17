#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : libcbox.py
@Time    : 2021/11/23 23:46:27
@Author  : Roderick Chan
@Email   : roderickchan@foxmail.com
@Desc    : Find libc by web api from https://github.com/niklasb/libc-database/tree/master/searchengine
'''

import atexit
import json
import os
import re
import shutil
import tempfile
import threading
from time import sleep, time

import requests

from .gadgetbox import RopgadgetBox, RopperBox, ElfGadgetBox
from .misc import errlog_exit, log_ex, one_gadget

__all__ = ["LibcBox"]

class LibcBox:
    def __init__(self, search_url="https://libc.rip/api/find", debug=False, wait_time=45):
        self._data = dict() # post data, is a dict
        self._res = None # post res, is a dict
        self._symbols = None
        self._call_searcher = False
        self._downloaded = False

        self.debug = debug # open debug or not
        self._wait_time = wait_time
        self._search_url = search_url
        self._search_url_list = ["https://libc.roderickchan.cn/api/find", "https://libc.rip/api/find"]
        if search_url:
            self._search_url_list.insert(0, search_url)

        self._rb = None # RopperBox
        self._tmp_dir = tempfile.mkdtemp()
        self._log("tmp save dir: {}".format(self._tmp_dir))
        # 用于判断是否本地存在不需要重复下载
        self._exist_so = False
        self._exist_sym = False
        self._exist_deb = False

        # 用于判断是否下载完成
        self._finish_so = False
        self._finish_sym = False
        self._finish_deb = False

        self._lock = threading.Lock()
        atexit.register(self.__clean)

    def __del__(self):
        self.__clean()
  

    def _log(self, *args, **kwargs):
        if self.debug:
            log_ex(*args, **kwargs)


    def __clean(self):
        if self._tmp_dir and os.path.exists(self._tmp_dir):
            shutil.rmtree(self._tmp_dir)
            self._log("delete tmp directory {} success!".format(self._tmp_dir))

    def __time_count(self, n: int, to_exit=True, varname="_downloaded"):
        if n <= 0:
             n = 30
        assert isinstance(n, int), "type error!"
        assert varname in ("_downloaded", "_finish_so", "_finish_deb", "_finish_sym")
        while n:
            if getattr(self, varname):
                break
            sleep(1)
            n -= 1
            if self._finish_deb and self._finish_so and self._finish_sym:
                self._downloaded = True
        
        if n == 0 and to_exit:
            errlog_exit("Download work donot finish in {}s".format(n))


    def __post_to_find(self):
        get_data = False
        for url in self._search_url_list:
            try:
                r = requests.post(url=url, data=json.dumps(self._data), headers={'Content-Type': 'application/json'})
                if r.status_code == 200:
                    get_data =True
                    break
            except:
                pass
        if not get_data:
            errlog_exit("Error status_code: {} from {}".format(r.status_code, url))
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
        if version_start is not None:
            log_ex("There are candidates with glibc version >= {}: ".format(version_start))
        for i, r in enumerate(self._res):
            if version_start is not None:
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
        dname = url.split("/")[-1]
        fn2 = os.path.join(".", dname)
        fn = os.path.join(self._tmp_dir, dname)
        if os.path.exists(fn2) and (not redownload):
            self._log("{} exists in current directory, it would not be downloaded again!".format(fn))
            if key == "libs_url":
                self._exist_deb = True
                self._finish_deb = True
            elif key == "download_url":
                self._exist_so = True
                self._finish_so = True
            else:
                self._exist_sym = True
                self._finish_sym = True
            return
        
        self._log("start to download {}...".format(dname))
        if mode == "t":
            tt1 = time()
            r = requests.get(url)
            with open(fn, "w", encoding='utf-8') as f:
                f.write(r.text)
                tt2 = time()
                self._log("Download {}: {} KB".format(dname, round(len(r.text) / 1024, 3)))
                self._log("Download {} success! Time used: {} s. Speed: {} KB/s.".format(dname, round(tt2 - tt1, 3), round(len(r.text) / 1024 / round(tt2 - tt1, 3), 3)))
        elif mode == 'b':
            bcount = 0
            tt1 = time()
            r = requests.get(url, stream=True)
            with open(fn, "wb") as f:
                for chunk in r.iter_content(0x40000):
                    if chunk:
                        f.write(chunk)
                        bcount += len(chunk)
                        self._log("Download {}: {} KB".format(dname, round(bcount / 1024, 3)))
            tt2 = time()
            self._log("Download {} success! Time used: {} s. Speed: {} KB/s.".format(dname, round(tt2 - tt1, 3), round(bcount / 1024 / round(tt2 - tt1, 3), 3)))

        if key == "libs_url":
            self._finish_deb = True
        elif key == "download_url":
            self._finish_so = True
        else:
            self._finish_sym = True

    def __download_async(self, download_symbols, download_so, download_deb, redownload, load_gadgets, wait_):
        self._exist_so = False
        self._exist_sym = False
        self._exist_deb = False

        self._finish_so = False
        self._finish_sym = False
        self._finish_deb = False

        if self._lock.acquire():
            self._lock.locked()
        
        if not self._downloaded or redownload:
            t1 = threading.Thread(target=self.__download_resources, args=('symbols_url', 't', redownload), daemon=True)
            t1.start()
            t2 = threading.Thread(target=self.__download_resources, args=('download_url', 'b', redownload), daemon=True)
            t2.start()
            t3 = threading.Thread(target=self.__download_resources, args=('libs_url', 'b', redownload), daemon=True)
            t3.start()
            t4 = threading.Thread(target=self.__time_count, args=(self._wait_time, True, "_downloaded"), daemon=True)
            t4.start()
            if wait_:
                t4.join()


        if download_symbols:
            while not self._finish_sym:
                sleep(0.1)

            name = self._res['symbols_url'].split("/")[-1]
            fn   = os.path.join(self._tmp_dir, name)
            if not self._exist_sym:
                shutil.copyfile(fn, name)
            
            if os.path.exists(fn):
                with open(fn, "r", encoding="utf-8") as f:
                    self._symbols = f.read()

        if download_so:
            while not self._finish_so:
                sleep(0.1)
            name = self._res['download_url'].split("/")[-1]
            fn   = os.path.join(self._tmp_dir, name)
            if not self._exist_so:
                shutil.copyfile(fn, name)

        if download_deb:
            while not self._finish_deb:
                sleep(0.1)
            name = self._res['libs_url'].split("/")[-1]
            fn   = os.path.join(self._tmp_dir, name)
            if not self._exist_deb:
                shutil.copyfile(fn, name)

        if load_gadgets:
            while not self._finish_so:
                sleep(0.1)
            self._log("start to load gadget...")
            threading.Thread(target=self.get_gadgetbox, args=(False,), daemon=True).start()
        
        self._lock.release()


    def reset(self):
        self._data = dict() # post data, is a dict
        self._res = None # post res, is a dict
        self._symbols = None
        self._call_searcher = False

        self._downloaded = False
        self._exist_so = False
        self._exist_sym = False
        self._exist_deb = False

        self._finish_so = False
        self._finish_sym = False
        self._finish_deb = False

        self._rb = None
        if self._tmp_dir and os.path.exists(self._tmp_dir):
            shutil.rmtree(self._tmp_dir)
        self._tmp_dir = tempfile.mkdtemp()
        self._log("tmp save dir: {}".format(self._tmp_dir))
        self._log("reset success!")


    def add_symbol(self, symbol_name:str, address:int):
        self.__process_symbols({symbol_name:hex(address & 0xfff)})
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

    
    def search(self, *, download_symbols=False, download_so=False, download_deb=False, redownload=False, version_start="2.23", load_gadgets=False, wait_=False):
        """search symbol

        Args:
            download_symbols (bool, optional): download symbol file in current directory or not. Defaults to False.
            download_so (bool, optional): download so file in current directory or not. Defaults to False.
            download_deb (bool, optional): download so file in current directory or not. Defaults to False.
            redownload (bool, optional): redownload even though file exists in current directory. Defaults to False.
            version_start (str, optional): libc version. Defaults to "2.23", no versio control when set None.
            load_gadgets (bool, optional): load gadgets using RopperBox. Defaults to False.
            wait_ (bool, optional): wait for download or not. Defaults to False.
        """
        if not self._data:
            errlog_exit("No condition! Please add condition first!")
        if version_start and not re.search("^\d\.\d\d$", version_start):
            errlog_exit("Invalid version_start, should be None or 2.23/2.27/2.31...!")
        self.__post_to_find()
        if not self._res:
            errlog_exit("Cannot find a libc file to meet your expectaions, please check your conditions!")

        options = self.__show_result(version_start)
        if len(self._res) > 1:
            while 1:
                ans = input("please choose one number or 'q' to quit: ")
                if ans[:-1] == "q" or ans[:-1] == "quit":
                    log_ex("quit libcbox!")
                    exit(-1)
                ans = int(ans)
                if ans in options:
                    self._res = self._res[ans - 1]
                    break
                log_ex("Wrong input!")
        else:
            self._res = self._res[0]
        
        threading.Thread(target=self.__download_async, args=(download_symbols, download_so, download_deb, redownload, load_gadgets, wait_), daemon=bool(not wait_)).start()
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
        try:
            res = [libc_base + x  for x in one_gadget(condition=self._res['buildid'], more=more, buildid=True)]
        except:
            name = self._res['download_url'].split("/")[-1]
            fn   = os.path.join(self._tmp_dir, name)
            self.__time_count(self._wait_time, True, "_finish_so")
            res = [libc_base + x  for x in one_gadget(condition=fn, more=more, buildid=False)]
        if show:
            log_ex("one_gadget: %r", [hex(x) for x in res])
        return res


    def get_gadgetbox(self, debug=False) -> RopgadgetBox:
        if not self._rb:
            if not self._call_searcher:
                errlog_exit("Please call search before you get_gadgetbox!")
            self.__time_count(self._wait_time, True, "_finish_so")
            name = self._res['download_url'].split("/")[-1]
            fn   = os.path.join(self._tmp_dir, name)
            try:
                self._rb = RopgadgetBox(debug=debug)
            except:
                try:
                    self._rb = RopperBox(debug=debug)
                except:
                    self._rb = ElfGadgetBox(debug=debug)
            self._rb.add_file("libc", fn, None)
        
        return self._rb

