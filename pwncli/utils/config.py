
import configparser
import os
from pwncli.utils.misc import errlog

__all__ = ['read_ini', 'try_get_config_data_by_key']

def read_ini(filenames:str) -> configparser.ConfigParser:
    if not os.path.exists(filenames):
        return None
    parser = configparser.ConfigParser()
    data = parser.read(filenames)
    if len(data) == 0:
        return None
    return parser


def try_get_config_data_by_key(data:configparser.ConfigParser, section:str, key:str) -> str:
    if not data:
        return None
    if not data.has_section(section):
        return None
    val = data[section]
    return val[key] if key in val else None


def show_config_data_by_section(data:configparser.ConfigParser, section:str):
    if not data:
        errlog("show_config_data_by_section: data is None!")
        return None
    if not data.has_section(section):
        errlog("show_config_data_by_section: has no section named '{}'!".format(section))
        return None
    val = data[section]
    print("\n[{}]".format(section))
    for k, v in val.items():
        print("{} = {}".format(k, v))
    print()


def show_config_data_all(data:configparser.ConfigParser):
    if not data:
        errlog("show_config_data_all: data is None!")
        return None
    for sec in data.sections():
        show_config_data_by_section(data, sec)








