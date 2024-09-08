import os
import code
from solidity_parser import parser
from termcolor import colored, cprint


def get_contract_info(name, binfo, info_type):
    """
    gets contract build info
    """
    ret = None
    for ct_file in binfo['output']['contracts'].keys():
        for ct_name in list(binfo['output']['contracts'][ct_file].keys()):
            if name == ct_name:
                if info_type not in binfo['output']['contracts'][ct_file][name].keys():
                    break
                ret = binfo['output']['contracts'][ct_file][name][info_type]
    return ret

def get_contract_storage(name, binfo):
    return get_contract_info(name, binfo, 'storageLayout')

def get_contract_abi(name, binfo):
    return get_contract_info(name, binfo, 'abi')


def get_contract_filepath(name, binfo):
    """
    Retrieved the filepath containing the declaration of a Contract
    """
    ret = None
    for ct_file in binfo['output']['contracts'].keys():
        for ct_name in list(binfo['output']['contracts'][ct_file].keys()):
            if name == ct_name:
                ret = ct_file
    return ret

def get_contract_content(name, binfo):
    """
    Returns the content of a Contract based on its name
    """
    ct_filepath = get_contract_filepath(name, binfo)
    return binfo['input']['sources'][ct_filepath]['content']


def is_contract_interface(name, binfo):
    """
    Checks if the contract name is associated to an interface contract
    """
    contract_content = get_contract_content(name, binfo)
    sU = parser.parse(contract_content, loc=True)
    ret = False
    for child in sU.children:
        if child.type == 'ContractDefinition' and child.kind == 'interface':
            ret = True
            break
    return ret


def get_source_unit(contract):
    return parser.parse(contract, start="sourceUnit", loc=False, strict=False)



def get_source_unit_object(name, binfo):
    sUO = None
    contract = get_contract_content(name, binfo)
    sourceUnit = get_source_unit(contract)
    sUO = parser.objectify(sourceUnit)
    return sUO

def warning(text):
    out = colored(text, "red", attrs=["reverse", "blink"])
    print(out)

def good(text):
    out = colored(text, "green", attrs=["reverse", "blink"])
    print(out)

def todo(text):
    out = colored(text, "magenta", attrs=["reverse", "blink"])
    print(out)

def error(text):
    out = colored(text, "light_magenta", attrs=["reverse", "blink"])
    print(out)

def info(text):
    out = colored(text, "light_blue", attrs=["reverse", "blink"])
    print(out) 