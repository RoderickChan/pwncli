import os
import time
from stat import S_ISFIFO

import click
from pwn import hexdump

from .decorates import bomber

__all__ = ["NamedPipePair"]

# FIFO
class NamedPipePair:
    def __init__(self, rpath, wpath, log_level="debug", created=True, deleted=True) -> None:
        self._init_pipe(rpath, created)
        self._init_pipe(wpath, created)
        self._rpath = rpath
        self._wpath = wpath
        self._deleted = deleted
        self._log_level = log_level.lower()
        self._rfd = os.open(rpath, os.O_RDONLY | os.O_NONBLOCK | os.O_NDELAY) # blocked
        self._wfd = os.open(wpath, os.O_SYNC | os.O_RDWR)
        if self._log_level == "debug":
            print(click.style("Create FIFO done!", fg="green"))
        
    def _init_pipe(self, path, created):
        if os.path.exists(path):
            if S_ISFIFO(os.stat(path).st_mode):
                pass
            else:
                raise RuntimeError("{} is not FIFO file".format(path))
        else:
            if created:
                os.mkfifo(path)
            else:
                raise FileNotFoundError(path)
    
    
    def __del__(self):
        os.close(self._rfd)
        os.close(self._wfd)
        if self._deleted:
            try:
                os.remove(self._rpath)
            except:
                pass
            
            try:
                os.remove(self._wpath)
            except:
                pass

    def send(self, data, timeout=15) -> int:
        if isinstance(data, str):
            data = data.encode('latin-1')
        assert timeout > 0, "Wrong timeout!"
        
        @bomber(timeout)
        def _inner(data):
            return os.write(self._wfd, data)
        
        if self._log_level == "debug":
            print(click.style("Send data:", fg="green"))
            print(hexdump(data, total=False))
        return _inner(data)

    def sendline(self, data, timeout=15) -> int:
        if isinstance(data, str):
            data = data.encode('latin-1')
        return self.send(data + b"\n", timeout)

    
    def recv(self, n=1024, timeout=5) -> bytes:
        assert timeout > 0, "Wrong timeout!"
        res = b""
        t1 = time.time()
        while n > 0:
            curb = b""
            try:
                curb = os.read(self._rfd, 1)
            except BlockingIOError:
                curb = b""
                pass
            if not curb:
                t2 = time.time()
                if t2 - t1 > timeout:
                    break
            else:
                res += curb
                n -= 1
                t1 = time.time()
        if self._log_level == "debug" and res:
            print(click.style("Receive data:", fg="green"))
            print(hexdump(res, total=False))
        return res
    
    
    def recvall(self, timeout=3) -> bytes:
        return self.recv(1<<64, timeout)


    def recvline(self, drop=False, timeout=5) -> bytes:
        assert timeout > 0, "Wrong timeout!"
        res = b""
        t1 = time.time()
        curb = b""
        while curb != b"\n":
            try:
                curb = os.read(self._rfd, 1)
            except BlockingIOError:
                pass
            if not curb:
                t2 = time.time()
                if t2 - t1 > timeout:
                    raise TimeoutError("recvline failed!")
            else:
                res += curb
                t1 = time.time()

        
        if self._log_level == "debug" and res:
            print(click.style("Receive data:", fg="green"))
            print(hexdump(res, total=False))

        if drop:
            res = res.rstrip(b"\n")
            
        return res
    

    def recvuntil(self, data, timeout=5) -> bytes:
        if isinstance(data, str):
            data = data.encode('latin-1')
        assert timeout > 0, "Wrong timeout!"
        assert len(data) > 0, "Wrong data!"
        
        len_ = len(data)
        tll = self._log_level
        self._log_level = "error"
        res = self.recv(len_, timeout)
        self._log_level = tll
        
        if len(res) != len_:
            raise TimeoutError("recvuntil failed!")
        
        t1 = time.time()
        curb = b""
        while res[-len_:] != data:
            try:
                curb = os.read(self._rfd, 1)
            except BlockingIOError:
                pass
            if not curb:
                t2 = time.time()
                if t2 - t1 > timeout:
                    raise TimeoutError("recvline failed!")
            else:
                res += curb
                t1 = time.time()

        if self._log_level == "debug" and res:
            print(click.style("Receive data:", fg="green"))
            print(hexdump(res, total=False))
            
        return res
    
    
    def sendafter(self, delim, data, timeout=5):
        self.recvuntil(delim, timeout)
        self.send(data, timeout)


    def sendlineafter(self, delim, data, timeout=5):
        self.recvuntil(delim, timeout)
        self.sendline(data, timeout)
        
