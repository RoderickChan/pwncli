from pwncli.utils.misc import *
import pytest
import re
import pathlib

CURDIR = pathlib.Path(__file__).parent
pwnpath = CURDIR / "../sources/pwn"
pwnpath = str(pwnpath.resolve())
libcpath = CURDIR / "../sources/libc-2.31.so"
libcpath = str(libcpath.resolve())

class TestPack:
    def test_p8_ex(self):
        assert p8_ex(0xdeadbeef) == b"\xef"
        assert p8_ex(0xdead) == b"\xad"
        assert p8_ex(0xfe) == b"\xfe"
        assert p8_ex(-1) == b"\xff"

    def test_p16_ex(self):
        assert p16_ex(0xdeadbeef) == b"\xef\xbe"
        assert p16_ex(0xdead) == b"\xad\xde"
        assert p16_ex(0xfe) == b"\xfe\x00"
        assert p16_ex(-1) == b"\xff\xff"

    def test_p24_ex(self):
        assert p24_ex(0xdeadbeef) == b"\xef\xbe\xad"
        assert p24_ex(0xdead) == b"\xad\xde\x00"
        assert p24_ex(0xfe) == b"\xfe\x00\x00"
        assert p24_ex(-1) == b"\xff\xff\xff"

    def test_p32_ex(self):
        assert p32_ex(0xcadeadbeef) == b"\xef\xbe\xad\xde"
        assert p32_ex(0xdeadbeef) == b"\xef\xbe\xad\xde"
        assert p32_ex(0xdead) == b"\xad\xde\x00\x00"
        assert p32_ex(0xfe) == b"\xfe\x00\x00\x00"
        assert p32_ex(-1) == b"\xff\xff\xff\xff"
        

    def test_p64_ex(self):
        assert p64_ex(0xcadeadbeef) == b"\xef\xbe\xad\xde\xca\x00\x00\x00"
        assert p64_ex(0xdeadbeef) == b"\xef\xbe\xad\xde\x00\x00\x00\x00"
        assert p64_ex(0xdead) == b"\xad\xde\x00\x00\x00\x00\x00\x00"
        assert p64_ex(0xfe) == b"\xfe\x00\x00\x00\x00\x00\x00\x00"
        assert p64_ex(-1) == b"\xff\xff\xff\xff\xff\xff\xff\xff"
        

class TestUnpack:
    def test_u8_ex(self):
        assert u8_ex("\xff") == 255
        assert u8_ex(b"\xff") == 255
        assert u8_ex("") == 0
        assert u8_ex(b"") == 0
        with pytest.raises(AssertionError) as e:
            u8_ex(b"\xff\xff")
        msg = e.value.args[0]
        assert msg == "len(data) > 1!"
        
        
    def test_u16_ex(self):
        assert u16_ex("\xff\xdd") == 0xddff
        assert u16_ex(b"\xff") == 0xff
        assert u16_ex("") == 0
        assert u16_ex(b"") == 0
        with pytest.raises(AssertionError) as e:
            u16_ex(b"\xff\xff\xff")
        msg = e.value.args[0]
        assert msg == "len(data) > 2!"
        
    def test_u24_ex(self):
        assert u32_ex("\x56\x34\x12") == 0x123456
        assert u24_ex("\x34\x12") == 0x1234
        assert u24_ex(b"\xff") == 0xff
        assert u24_ex("") == 0
        assert u24_ex(b"") == 0
        with pytest.raises(AssertionError) as e:
            u24_ex(b"\xff\xff\xff\xff")
        msg = e.value.args[0]
        assert msg == "len(data) > 3!"

    def test_u32_ex(self):
        assert u32_ex("\x78\x56\x34\x12") == 0x12345678
        assert u32_ex("\x56\x34\x12") == 0x123456
        assert u32_ex("\x34\x12") == 0x1234
        assert u32_ex(b"\xff") == 0xff
        assert u32_ex("") == 0
        assert u32_ex(b"") == 0
        with pytest.raises(AssertionError) as e:
            u32_ex(b"\xff\xff\xff\xff\xff")
        msg = e.value.args[0]
        assert msg == "len(data) > 4!"

    def test_u64_ex(self):
        assert u64_ex("\xef\xcd\xab\x90\x78\x56\x34\x12") == 0x1234567890abcdef
        assert u64_ex("\xab\x90\x78\x56\x34\x12") == 0x1234567890ab
        assert u32_ex("\x78\x56\x34\x12") == 0x12345678
        assert u64_ex("\x56\x34\x12") == 0x123456
        assert u64_ex("\x34\x12") == 0x1234
        assert u64_ex(b"\xff") == 0xff
        assert u64_ex("") == 0
        assert u64_ex(b"") == 0
        with pytest.raises(AssertionError) as e:
            u64_ex(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff")
        msg = e.value.args[0]
        assert msg == "len(data) > 8!"
        
        
class TestInt:
    def test_int(self):
        assert int_ex("01234") == 1234
        assert int_ex(b"1234") == 1234
        assert int("1234") == 1234
        assert int(b"1234") == 1234
    

    def test_int2(self):
        assert int2_ex("1111") == 15
        assert int2_ex(b"1111") == 15
        assert int2("1111") == 15
        assert int2(b"1111") == 15


    def test_int8(self):
        assert int8_ex("1111") == 585
        assert int8_ex(b"1111") == 585
        assert int8("1111") == 585
        assert int8(b"1111") == 585

    def test_int16_ex(self):
        assert int16_ex("0xdeadbeef") == 0xdeadbeef
        assert int16_ex(b"0xdeadbeef") == 0xdeadbeef
        assert int16("0xdeadbeef") == 0xdeadbeef
        assert int16(b"0xdeadbeef") == 0xdeadbeef

class TestLog:
    def test_logxxx(self):
        print()
        log_ex("This is log_ex")
        log_ex("This is log_ex %s %s", "format", "usage")
        log_ex_highlight("This is log_ex_highlight")
        log2_ex("This is log2_ex")
        log2_ex_highlight("This is log2_ex_highlight")
        warn_ex("This is warn_ex")
        warn_ex_highlight("This is warn_ex_highlight")
        errlog_ex("This is errlog_ex")
        errlog_ex_highlight("This is errlog_ex_highlight")
    
    def test_log_address(self):
        libc_base = 0xdeadbeef
        log_address("libc_base", libc_base)
        leak("libc_base", libc_base)
        log_address_ex("libc_base")
        leak_ex("libc_base")
        log_address_ex2(libc_base)
        leak_ex2(libc_base)
        
        log_libc_base_addr(0xdeadbeef)
        log_code_base_addr(0xdeadbeef)
        log_heap_base_addr(0xdeadbeef)


class TestOther:
    def test_step_split(self):
        assert tuple(step_split("12345678", 4)) == ("1234", "5678")
        assert tuple(step_split("1234567", 4)) == ("1234", "567")
    
    def test_protect_ptr(self):
        assert protect_ptr(0x555563e56320, 0x555563e56340) == 0x555036b35d16
    
    def test_reveal_ptr(self):
        assert reveal_ptr(0x555036b35d16) == 0x555563e56340
    
    @pytest.mark.skip()
    def test_get_callframe_info(self):
        assert get_callframe_info(1) == ('misc.py', 'get_callframe_info', 172)
        assert get_callframe_info(2) == ('test_misc.py', 'test_get_callframe_info', 147)
        
    def test_ldd_get_libc_path(self):
        libc = ldd_get_libc_path(pwnpath)
        assert libc == libcpath

    
    def test_one_gadget(self):
        ogs = one_gadget(libcpath)
        ogs.sort()
        assert ogs == [932606, 932609, 932612]
        
        ogs_more = one_gadget(libcpath, more=True)
        ogs_more.sort()
        assert ogs_more == [335369, 335381, 335402, 335410, 
                            540995, 541008, 541020, 541033, 
                            932606, 932609, 932612, 933107, 
                            933110, 933225, 933232, 933301, 
                            933309, 1078698, 1078706, 1078711, 1078721]

        ogs_buildid = one_gadget("aad7dbe330f23ea00ca63daf793b766b51aceb5d")
        ogs_buildid.sort()
        assert ogs_buildid == [283942, 284026, 988753, 992459]

        ogs_buildid = one_gadget("aad7dbe330f23ea00ca63daf793b766b51aceb5d", True)
        ogs_buildid.sort()
        assert ogs_buildid == [283942, 284026, 843329, 844001, 
                               844005, 844009, 988753, 988765, 
                               992459]

    def test_one_gadget_binary(self):
        ogs = one_gadget_binary(pwnpath)
        ogs.sort()
        assert ogs == [932606, 932609, 932612]

        ogs_more = one_gadget_binary(pwnpath, more=True)
        ogs_more.sort()
        assert ogs_more == [335369, 335381, 335402, 335410, 
                            540995, 541008, 541020, 541033, 
                            932606, 932609, 932612, 933107, 
                            933110, 933225, 933232, 933301, 
                            933309, 1078698, 1078706, 1078711, 1078721]
        
    