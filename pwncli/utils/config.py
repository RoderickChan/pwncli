
import configparser
import os

__all__ = ['read_ini', 'try_get_config']

def read_ini(filenames:str) -> configparser.ConfigParser:
    if not os.path.exists(filenames):
        return None
    parser = configparser.ConfigParser()
    data = parser.read(filenames)
    if len(data) == 0:
        return None
    return parser


def try_get_config(data, section, key) -> str:
    if not data:
        return None
    if not data.has_section(section):
        return None
    val = data[section]
    return val[key] if key in val else None



