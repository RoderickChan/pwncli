
import configparser
import os

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


def set_config_data_by_section(data:configparser.ConfigParser, section:str, **kwargs):
    section = str(section)
    if not _check_data_section_ok(data, section):
        return None
    
    # guarantee type of key and value is str
    for k, v in kwargs.items():
        data[section][str(k)] = str(v)
    

def set_config_data_by_key(data:configparser.ConfigParser, section:str, key:str, value:str):
    section = str(section)
    if not _check_data_section_ok(data, section):
        return None
    
    # guarantee type of key and value is str
    data[section][str(key)] = str(value)


def write_config_data(data:configparser.ConfigParser, filepath:str="~/.pwncli.conf") -> bool:
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


    






