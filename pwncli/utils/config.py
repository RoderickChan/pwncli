
import configparser
import os

__all__ = ['read_ini', 'try_get_config_data_by_key', 'show_config_data_by_section', "show_config_data_all", "show_config_data_file"]

_check_data_section_ok = lambda data, section: bool(data and data.has_section(section))

def read_ini(filename:str) -> configparser.ConfigParser:
    if not os.path.exists(filename):
        return None
    parser = configparser.ConfigParser()
    data = parser.read(filename)
    if len(data) == 0:
        return None
    return parser


def try_get_config_data_by_key(data:configparser.ConfigParser, section:str, key:str) -> str:
    if not _check_data_section_ok(data, section):
        return None
    val = data[section]
    return val[key] if key in val else None


def show_config_data_by_section(data:configparser.ConfigParser, section:str):
    if not _check_data_section_ok(data, section):
        return None
    val = data[section]
    print("[{}]".format(section))
    for k, v in val.items():
        print("{} = {}".format(k, v))
    print()


def show_config_data_all(data:configparser.ConfigParser):
    if not _check_data_section_ok(data, section):
        return None
    for sec in data.sections():
        show_config_data_by_section(data, sec)


def show_config_data_file(filename:str):
    show_config_data_all(read_ini(filename))


def set_config_data_by_section(data:configparser.ConfigParser, section, **kwargs):
    if not _check_data_section_ok(data, section):
        return None
    section = str(section)
    



def set_config_data_by_key(data:configparser.ConfigParser, section, key, value):
    section = str(section)
    if not _check_data_section_ok(data, section):
        return None
    
    key = str(key)
    value = str(value)
    data[section][key] = value


def write_config_data(data:configparser.ConfigParser, filepath="~/.pwncli.conf"):
    if not data:
        return None

    if filepath.startswith("~"):
        filepath = os.path.expanduser(filepath)
    
    filepath = os.path.abspath(filepath)

    if not os.path.isfile(filepath):
        return None
    
    with open(filepath, "w") as configfile:
        data.write(configfile)
    return True


    






