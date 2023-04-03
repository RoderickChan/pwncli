

import builtins

import pytest

from pwncli import LibcBox


@pytest.mark.second_to_last
def test_libcbox(monkeypatch):
    def mock_input(status):
        return '1'

    monkeypatch.setattr(builtins, 'input', mock_input)

    lb = LibcBox(debug=True)
    lb.add_symbol("puts", 0x5a0)
    lb.search()
    
    assert lb.dump_str_bin_sh() == 0x1b75aa
    assert lb.dump("system", show=True) == 0x55410
    
    ogs = lb.dump_one_gadget(0)
    ogs.sort()
    ogs == [945278, 945281, 945284]
    
    gb = lb.get_gadgetbox()
    assert gb.get_bin_sh() == 0x1b75aa


