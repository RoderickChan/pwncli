
import configparser
from pwncli.utils.misc import log, log2, errlog

__all__ = ['read_ini']

def read_ini(filenames:str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    data = parser.read(filenames)
    if len(data) == 0:
        errlog("config --> Read failed!")
        return None
    return data


