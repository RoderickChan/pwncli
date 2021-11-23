#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : config.py
@Time    : 2021/11/23 23:48:28
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : None
'''



import configparser
import os

_check_data_section_ok = lambda data, section: bool(data and data.has_section(section))


def read_ini(filename:str) -> configparser.ConfigParser:
    """Read ini file using configerparser with little check

    Args:
        filename (str): Target filepath

    Returns:
        configparser.ConfigParser: Return None if failed
    """
    if not os.path.exists(filename):
        return None
    parser = configparser.ConfigParser()
    data = parser.read(filename)
    if len(data) == 0:
        return None
    return parser


def try_get_config_data_by_key(data:configparser.ConfigParser, section:str, key:str) -> str:
    """Try to get value by section name and option name with little check

    Args:
        data (configparser.ConfigParser): Data
        section (str): Section name
        key (str): Option name

    Returns:
        str: Value, Return None if error occurs
    """
    if not _check_data_section_ok(data, section):
        return None
    val = data[section]
    return val[key] if key in val else None


def show_config_data_by_section(data:configparser.ConfigParser, section:str):
    """Print a section's data by section name

    Args:
        data (configparser.ConfigParser): Data
        section (str): Section name

    """
    if not _check_data_section_ok(data, section):
        return None
    val = data[section]
    print("[{}]".format(section))
    for k, v in val.items():
        print("{} = {}".format(k, v))
    print()


def show_config_data_all(data:configparser.ConfigParser):
    """Show the whole config data

    Args:
        data (configparser.ConfigParser): Data

    """
    if not data:
        return
    for sec in data.sections():
        show_config_data_by_section(data, sec)


def show_config_data_file(filename:str):
    """Show the whole config data

    Args:
        filename (str): Config data file path
    
    """
    show_config_data_all(read_ini(filename))


def set_config_data_by_section(data:configparser.ConfigParser, section:str, **content):
    """Set a section's content of config-data with little check

    Args:
        data (configparser.ConfigParser): Data
        section (str): Section name
        content (dict): Content to set

    """
    section = str(section)
    if not _check_data_section_ok(data, section):
        return None
    
    # guarantee type of key and value is str
    for k, v in content.items():
        data[section][str(k)] = str(v)
    

def set_config_data_by_key(data:configparser.ConfigParser, section:str, key:str, value:str):
    """Set option value in a section of a config-data with little check

    Args:
        data (configparser.ConfigParser): Data
        section (str): Section name
        key (str): Option name
        value (str): Value to set

    """
    section = str(section)
    if not _check_data_section_ok(data, section):
        return None
    
    # guarantee type of key and value is str
    data[section][str(key)] = str(value)


def write_config_data(data:configparser.ConfigParser, filepath:str="~/.pwncli.conf") -> bool:
    """Write data to file

    Args:
        data (configparser.ConfigParser): Data
        filepath (str, optional): The target file path. Defaults to "~/.pwncli.conf".

    Returns:
        bool: whether the writting is successful
    """
    if not data:
        return False

    if filepath.startswith("~"):
        filepath = os.path.expanduser(filepath)
    
    filepath = os.path.abspath(filepath)

    if not os.path.isfile(filepath):
        return False
    
    with open(filepath, "w") as configfile:
        data.write(configfile)
    return True