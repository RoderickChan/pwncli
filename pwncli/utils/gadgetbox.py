#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : gadgetbox.py
@Time    : 2021/11/23 12:33:55
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : Use ropper api from https://github.com/sashs/Ropper
'''

import functools
from ropper import RopperService, RopperError, Gadget
from enum import Enum, unique
from .misc import errlog_exit, log_ex, _get_elf_arch_info
import os
import threading
import time
import keystone as ks
from typing import List, Union, Dict

__all__ = ['RopperOptionType', 'RopperArchType', 'RopperBox', "RopgadgetBox"]

class _GadgetObj:
    def __init__(self, name, filepath, arch, imgbase) -> None:
        self.name = name
        self.filepath = filepath
        self.arch = arch
        self.imgbase = imgbase
        self.ks = None
        self.allgadgets = None # {all: {stat:addr}, string: {str:addr}, opcode:{opcode: addr}}
        self.allgadget_done = False
        self.cache = None


class _GadgetBase:
    def __init__(self, debug):
        self._debug = debug
        self.allinfo: Dict[str, _GadgetObj] = dict()
    
    def _log(self, msg):
        if self._debug:
            log_ex(msg)

    def set_debug(self, val: bool):
        self._debug = val

    def add_file(self, name:str, filepath:str, arch):
        if os.path.exists(filepath) and os.path.isfile(filepath):
            pass
        else:
            raise FileExistsError("{} not exists!".format(filepath))
        self.allinfo[name] = _GadgetObj(name, filepath, arch, 0)

    def remove_file(self, name: str):
        if name:
            self.allinfo.pop(name, None)
        else:
            self.allinfo.clear()

    def get_allgadgets(self, name: str=None):
        pass

    def print_gadgets(self, name: str=None):
        pass

    def set_imagebase(self, name:str, base: int=0):
        self.allinfo[name].imgbase = base


    def search_gadget(self, search: str, name: str, get_list: bool=False) -> Union[List[int], int]:
        pass

    def search_string(self, string: str, name: str, get_list: bool=False) -> Union[List[int], int]:
        pass

    def search_opcode(self, opcode: str, name: str, get_list: bool=False) -> Union[List[int], int]:
        pass

    def get_pop_rdi_ret(self, name: str=None) -> int:
        return self.search_opcode("5fc3", name)


    def get_pop_rsi_ret(self, name: str=None) -> int:
        return self.search_opcode("5ec3", name)

    def get_pop_rdx_ret(self, name: str=None) -> int:
        return self.search_opcode("5ac3", name)

    def get_pop_rdx_rbx_ret(self, name: str=None) -> int:
        return self.search_opcode("5a5bc3", name)

    def get_pop_rax_ret(self, name: str=None) -> int:
        return self.search_opcode("58c3", name)

    def get_pop_rbx_ret(self, name: str=None) -> int:
        return self.search_opcode("5bc3", name)

    def get_pop_rcx_ret(self, name: str=None) -> int:
        return self.search_opcode("59c3", name)
    
    def get_pop_rbp_ret(self, name: str=None) -> int:
        return self.search_opcode("5dc3", name)

    def get_pop_rsp_ret(self, name: str=None) -> int:
        return self.search_opcode("5cc3", name)

    def get_pop_rsi_r15_ret(self, name: str=None) -> int:
        return self.search_opcode("5E415FC3", name)

    def get_ret(self, name: str=None) -> int:
        return self.search_opcode("c3", name)

    def get_syscall(self, name: str=None) -> int:
        return self.search_opcode("0f05", name)

    def get_syscall_ret(self, name: str=None) -> int:
        return self.search_opcode("0f05c3", name)

    def get_leave_ret(self, name: str=None) -> int:
        return self.search_opcode("c9c3", name)

    def get_magic_gadget(self, name: str=None) -> int:
        """add dword ptr [rbp - 0x3d], ebx"""
        return self.search_opcode("015dc3", name)

    def get_bin_sh(self, name: str=None) -> int:
        """/bin/sh"""
        try:
            return self.search_string("/bin/sh", name)
        except:
            return self.search_string("/bin//sh", name)

    def get_sh(self, name: str=None) -> int:
        """sh"""
        return self.search_string("sh", name)
    
    def get_int80(self, name: str=None) -> int:
        return self.search_opcode("cd80", name)

    def get_int80_ret(self, name: str=None) -> int:
        return self.search_opcode("cd80c3", name)



class RopgadgetBox(_GadgetBase):
    def __init__(self, debug):
        super().__init__(debug)
        if os.system("which ROPgadget >/dev/null 2>&1") != 0:
            raise FileExistsError("RopgadgetBox error! Please install ROPgadget first!")

    def add_file(self, name: str, filepath: str, arch: str):
        if not arch:
            arch = _get_elf_arch_info(filepath)
        if arch != "i386" or arch != "amd64":
            raise RuntimeError("arch must be i386 or amd64!")
        super().add_file(name, filepath, arch)
        if arch == "i386":
            self.allinfo[name].ks = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32 + ks.KS_MODE_LITTLE_ENDIAN)
        else:
            self.allinfo[name].ks = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_64 + ks.KS_MODE_LITTLE_ENDIAN)
        
        # 后台处理得到gadgets
        # TODO
        def _getallgadgets(obj: _GadgetObj):
            obj.allgadget_done = True
            pass
        threading.Thread(target=_getallgadgets, args=(self.allinfo[name],), daemon=True).start()

    def remove_file(self, name: str):
        super().remove_file(name)

    def get_allgadgets(self, name):
        if name in self.allinfo:
            while not self.allinfo[name].allgadget_done:
                time.sleep(5)
                self._log("wait for load gadgets...")
            return self.allinfo[name].allgadgets
        raise RuntimeError("{} is error!".format(name))

    def _inner_search(self, sname, key, name, get_list):
        if not name:
            for _n in self.allinfo.keys():
                res =  self._inner_search(self, sname, key, _n, get_list)
                if res:
                    return res
            return None
        
        if name not in self.allinfo:
            raise RuntimeError("{} is error!".format(name))
        
        if self.allinfo[name].allgadget_done:
            res = self.allinfo[name].allgadgets[sname].get(key, None)
        else:
            # TODO
            res = []

        if not res:
            return None
        
        if get_list:
            return res
        else:
            return res[0]


    def search_gadget(self, search: str, name: str, get_list: bool=False) -> Union[List[int], int]:
        # TODO 先gadget 再hex

        #
        opcode = bytes(self.ks.asm(search)).hex()
        return self.search_opcode(opcode, name, get_list)


    def search_string(self, string: str, name: str, get_list: bool=False) -> Union[List[int], int]:
        return self._inner_search("string", string, name, get_list)

    def search_opcode(self, opcode: str, name: str, get_list: bool=False) -> Union[List[int], int]:
        return self._inner_search("opcode", opcode, name, get_list)


@unique
class RopperOptionType(Enum):
    rop = 'rop'
    jop = "jop"
    sys = 'sys'
    all = 'all'


@unique
class RopperArchType(Enum):
    x86 = 'x86'
    x86_64 = 'x86_64'
    arm = 'ARM'
    armbe = 'ARMBE'
    armthumb = 'ARMTHUMB'
    arm64 = 'ARM64'
    mips = 'MIPS'
    mipsbe = 'MIPSBE'
    mips64 = 'MIPS64'
    mips64be = 'MIPS64BE'
    ppc = 'PPC'
    ppc64 = 'PPC64'
    sparc64 = 'SPARC64'

_inner_mapping = {
    "i386": RopperArchType.x86,
    "amd64": RopperArchType.x86_64,
    "arm": RopperArchType.arm,
    "aarch64": RopperArchType.arm64,
    "mips": RopperArchType.mips,
    "powerpc": RopperArchType.ppc,
    "powerpc64": RopperArchType.ppc64,
    "sparc64": RopperArchType.sparc64
}

class RopperBox(_GadgetBase):
    def __init__(self, *, badbytes: str='', show_all: bool=False, 
                inst_count: int=10, op_type: RopperOptionType=RopperOptionType.all, detailed: bool=False, debug=False):
        super().__init__(debug)
        self._rs = RopperService(options={
            'color': False,
            'badbytes': badbytes,
            'all': show_all,
            'inst_count': inst_count, 
            'type': op_type.value,
            'detailed': detailed
            })
        self._all_cache = {"string":{}, "gadget": {}, "opcode": {}}
        self._search_func = {"string": self._rs.searchString, "gadget": self._rs.searchdict, "opcode": self._rs.searchOpcode}

    def __del__(self):
        self.remove_file(None)


    def update_option(self, **kwargs):
        for k, v in kwargs.items():
            self._rs.options[k] = v

    def add_file(self, name:str, filepath:str, arch:RopperArchType):
        if not arch:
            arch = _get_elf_arch_info(filepath)
            if arch not in _inner_mapping:
                errlog_exit("cannot get arch info, please specify it.")
            arch = _inner_mapping[arch]
        super().add_file(name, filepath, None)
        self._rs.addFile(name, open(filepath, 'rb').read(), arch.value, False)
        self._rs.loadGadgetsFor(name)
        self._log("Load gadgets from %s success!" % filepath)
        for k in self._all_cache:
            self._all_cache[k][name] = {}


    def remove_file(self, name: str=None):
        super().remove_file(name)
        if name is None:
            for f in self._rs.files:
                self._rs.removeFile(f.name)
                self._log("remove file: %s success!" % f.name)
        else:
            self._rs.removeFile(name)
            self._log("remove file: %s success!" % name)
        
    
    def get_allgadgets(self, name: str=None) -> List[Gadget]:
        if not name and len(self._rs.files) == 1:
            name = self._rs.files[0].name
        
        return self._rs.getFileFor(name).gadgets

    def print_gadgets(self, name: str=None):
        self._rs.printGadgetsFor(name)


    def clear_cache(self):
        self._rs.clearCache()
        for k in self._all_cache:
            self._all_cache[k].clear()
        self._log("clear cache success!")


    def _inner_search(self, stmt, name, search_type, get_list):
        if search_type not in self._all_cache:
            raise RopperError("Wrong search_type: %s" % search_type)
        data = self._all_cache[search_type]
        
        if name and (name in data) and (stmt in data[name]):
            return data[name][stmt][0] + self.allinfo[name].imgbase
        
        if not name:
            for n, s in data.items():
                if stmt in s:
                    return s[stmt][0] + self.allinfo[name].imgbase
        
        _l = None
        res = (self._search_func[search_type])(stmt, name=name)
        for n, ds in res.items():
            if ds:
                _l = data[n].get(stmt, [])
                for d in ds:
                    if search_type == 'string':
                        _v = d[0]
                    else:
                        _v = d.address
                    if _v not in _l:
                        self._log("find one {} ---> {}".format(search_type, d))
                        _l.append(_v)

        if not _l:
            raise RopperError("Cannot find %s." % stmt)
        
        return [x + self.allinfo[name].imgbase for x in _l] if get_list else _l[0] + self.allinfo[name].imgbase

    @functools.lru_cache(maxsize=128, typed=True)
    def search_gadget(self, search: str, name: str=None, get_list: bool=False) -> Union[List[int], int]:
        return self._inner_search(search, name, "gadget", get_list)

    @functools.lru_cache(maxsize=128, typed=True)
    def search_string(self, string: str, name: str=None, get_list: bool=False) -> Union[List[int], int]:
        return self._inner_search(string, name, "string", get_list)

    @functools.lru_cache(maxsize=128, typed=True)
    def search_opcode(self, opcode: str, name: str=None, get_list: bool=False) -> Union[List[int], int]:
        if len(opcode) > 14:
            opcode = opcode[:14]
            log_ex("opcode'length is more than 7 bytes, only seach 7 bytes.")
        return self._inner_search(opcode, name, "opcode", get_list)

