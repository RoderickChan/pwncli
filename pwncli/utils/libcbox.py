"""Find libc by web api from https://github.com/niklasb/libc-database/tree/master/searchengine

"""

import requests
import json
import threading
from tempfile import TemporaryFile
from pwncli.utils.misc import errlog_exit, log2_ex

class LibcBox:
    def __init__(self):
        self._data = {} # post data, is a dict
        self._res = None # post res, is a dict
        self._symbols = None

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
        
    # TODO
    def __process_hash(self, hash_type, hash_value):
        pass
    
    def __show_result(self):
        print("="*90)
        print("There are {} candidates: ".format(len(self._res)))
        for i, r in enumerate(self._res):
            print(
"""[{}] ==> version: {}
        buildid: {}
        sha256 : {}
""".format(i+1, r['id'], r['buildid'], r['sha256']))
        print("="*90)
        pass

    def add_symbol(self, symbol_name:str, address:int):
        self.__process_symbols({symbol_name:hex(address)})
        return self

    def add_md5(self, hash_val):
        self.__process_hash('md5', hash_value)
        return self

    def add_sha1(self, hash_val):
        self.__process_hash('sha1', hash_value)
        return self

    def add_sha256(self, hash_val):
        self.__process_hash('sha256', hash_value)
        return self

    def add_buildid(self, buildid):
        self.__process_hash('buildid', buildid)
        return self

    
    def search(self, *, download_symbols=False, download_so=False):
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
            def _download_symbols():
                url = self._res['symbols_url']
                r = requests.get(url)
                fn = url.split("/")[-1]
                with open(fn, "w", encoding='utf-8') as f:
                    f.write(r.text)
                self._symbols = r.text
                log2_ex("Download {} success!".format(fn))
            t = threading.Thread(target=_download_symbols)
            t.start()

        if download_so:
            def _download_so():
                url = self._res['download_url']
                r = requests.get(url, stream=True)
                fn = url.split("/")[-1]
                with open(fn, "wb") as f:
                    for chunk in r.iter_content(1024):
                        if chunk:
                            f.write(chunk)
                log2_ex("Download {} success!".format(fn))
            t = threading.Thread(target=_download_so)
            t.start()
    
    def dump(self, symbol_name:str) -> int:
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


# f = LibcBox()
# f.add_symbol("strcpy", 0xab0).search(download_symbols=0)
# print(f.dump("malloc"))
# print(f.dump('free'))
