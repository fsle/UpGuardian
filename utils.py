import os
import code
from solidity_parser import parser
from termcolor import colored, cprint
import sha3
import json

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
    if ret == None:
        error("The specified contract name could not be find in the build info file")
        exit(1)
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

def has_function_only_one_return_val(f):
    ret = False
    if len(f.returns.keys()) == 1:
        ret = True
    return ret

def get_function_return_first_type(f):
    ret = None
    first_key = list(f.returns.keys())[0]
    ret = f.returns[first_key].typeName.namePath
    return ret

def compute_function_sighash(sig):
    k = sha3.keccak_256()
    k.update(bytes(sig, 'ascii'))
    return k.hexdigest()[0:8]

def get_abi_from_artefact(name, fp):
    abi = None
    binfo = json.loads(open(fp,'r').read())
    abi = get_contract_abi(name, binfo)
    return abi


def get_functions_sigs_from_artefact(name, build_info_fp):
    abi = get_abi_from_artefact(name, build_info_fp)
    sigs = []
    for item in abi:
        if item['type'] == 'function':
            # Construct the function signature
            inputs = ','.join([input['type'] for input in item['inputs']])
            signature = f"{item['name']}({inputs})"
            sigs.append(signature)
    return sigs

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