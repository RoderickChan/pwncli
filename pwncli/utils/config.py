
import configparser
import os

__all__ = ['read_ini', 'try_get_config_data_by_key', 'show_config_data_by_section', "show_config_data_all", "show_config_data_file"]

def read_ini(filename:str) -> configparser.ConfigParser:
    if not os.path.exists(filename):
        return None
    parser = configparser.ConfigParser()
    data = parser.read(filename)
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
        return None
    if not data.has_section(section):
        return None
    val = data[section]
    print("[{}]".format(section))
    for k, v in val.items():
        print("{} = {}".format(k, v))
    print()


def show_config_data_all(data:configparser.ConfigParser):
    if not data:
        return None
    for sec in data.sections():
        show_config_data_by_section(data, sec)


def show_config_data_file(filename:str):
    show_config_data_all(read_ini(filename))
    






