import sys
import code
import os
import json

import argparse

from solidity_parser import parser


from utils import get_contract_storage, get_contract_abi, get_contract_content, is_contract_interface, get_source_unit_object, get_source_unit
from utils import has_function_only_one_return_val, get_function_return_first_type
from utils import compute_function_sighash, get_functions_sigs_from_artefact
from utils import warning, todo, error, good, info

"""
Upgrade Guardian:

1.Load 
    - parses AST from source(s)
    - loads json build info files

2. detects upgreadeability (UUPS vs TTP) (TODO)

3. make security checks (for UUPS)
    - if UUPS upgrade logic is in implementation
        - should have a call to upgradeToAndCall which should do a super.upgradeToAndCall() (UUPS)
        - verify that the `_authorizeUpgrade` is overriden and has good control access
    - disableInitializers in constructor (for implem)
    - initialize() an reinitialize() method with initialize modifier
    - detect immutable usage in contract

    - check for storage changes (implem v1 vs v2)
    - check for storage clash (proxy vs implementation)

    - check for function clashing between proxy and implmentation
    - check that all initializer are called in main contract (and not more than once)
    - check for delegatecall / selfdestruct() calls
    
    TODO - check if Namespaced Storage Layout is used (ERC7201) -> if not check if there are storage __gap
        assembly block with slot + keccak
4. make security checks (for TTP)
    TODO - watch out about admin and not admin functionalities

TODO - add check for storage gaps ?
TODO:
1. online check, is initialize
    - uninitialized implem contract (https://medium.com/immunefi/wormhole-uninitialized-proxy-bugfix-review-90250c41a43a)
    - Uninitialized State Variables

2. Ownable2StepUpgradaeble, in v4: initializer does call Ownalbe's initializer, but not in v5; should `_transferOwnership(newOwner)` or `__Ownable_init(newOwner)`
https://github.com/OpenZeppelin/openzeppelin-contracts/issues/4690
"""



def is_UUPS(sUO):
    """
    TODO: we should check if the import is used in contract declaration
        - to be more clean we should load all imports deps and look for UUPS
    """
    ret = False
    for imp in sUO.imports:
        if "UUPS" in imp.path:
            ret = True
            print(f"UUPS -> {imp.path}")
    return ret

def check_constructor(name, ct):
    """
    Checks if there is a constructor. If so checks that the constructor disables the initializers.
    If not disabled, an attacker can:
        - initialize implementation contract (claim ownership of implem)
        - call upgradeToAndCall() with selfdestructing contract
        - render proxy contract useless (pointing to destructed contract)
    """
    info("Constructor check")
    constructor = None
    disabler = False
    for func in ct.functions.keys():
        f = ct.functions[func]
        if f.isConstructor:
            constructor = f
    if constructor is not None:
        print(f"[{ct.name}] has a constructor")

        statements = constructor._node.body.statements
        for stat in statements:
            if stat.type == 'ExpressionStatement' and stat.expression.type == 'FunctionCall' and stat.expression.expression.name == '_disableInitializers':
                disabler = True
                good("constructor makes use of _disableInitializers()")
        
        if not disabler:
            warning(f"[{ct.name}] constructor does not use _disableInitializers")
            todo(f"\tCheck if initialize functions are protected")


def check_initializers(ct):
    """
    Checks that init functions (initialize, reinitialize) have a modifier. If not, an attacker could:
        -  re-initialize the state of the contract through initialize or reinitialize
    """
    for func in ct.functions.keys():
        f = ct.functions[func]
        modifs = f._node.modifiers
        isInitializerFunction = False
        hasInitializerModifier = False
        if 'initial' in f._node.name:
            isInitializerFunction = True
            for m in modifs:
                if 'init' in m.name:
                    hasInitializerModifier = True
                    good(f"{func} function has {m.name} modifier")

        if isInitializerFunction and not hasInitializerModifier:
            warning(f"{func} function has no modifier initializer")
            todo("\tCheck if there is a modifier is preventing from reinit")

def upgrade_access_control(ct):
    """
    Checks that the _authorizeUpgrade function has a modifier that restricts its access.
    If not, an attacker could upgrade the contract and change its implementation.
    """
    for func in ct.functions.keys():
        f = ct.functions[func]
        modifs = f._node.modifiers
        isUpgradeFunction = False
        hasAccessControl = False
        if '_authorizeUpgrade' in f._node.name:
            isUpgradeFunction = True
            for m in modifs:
                if 'only' in m.name:
                    hasAccessControl = True
                    good(f"{func} upgrade function has {m.name} modifier")
                    todo(f"\tCheck is this modifier correctly restricts access ({ct.name}:L{m.loc['start']['line']})")

        if isUpgradeFunction and not hasAccessControl:
            warning(f"{func} upgrade function has no 'only' access control")
            todo("\tCheck if the following modifiers restrict access to the upgrade")
            for m in m.name:
                todo(f"\t{m.name}")


def check_for_immutables(ct):
    """
    Identifies immutables variables and raises awareness about these kind of variables.
    Upgradeable contracts have no constructors (should not use them) and rely on initializers.
    However, in some cases immutable variables are upgrade safe.
    this can be used to bypass oz warning -> //@custom:oz-upgrades-unsafe-allow state-variable-immutable
    """
    for var_name in ct.stateVars.keys():
        var = ct.stateVars[var_name]
        if var.isDeclaredImmutable:
            warning(f"{var_name} variable is immutable")
            todo("\tCheck if it is intended (i.e: if this value is never going to be updated (will be in bytecode at deploy time))")

def display_storage_data(storage):
    """
    Display the storage data type, label and slot number
    """
    return f"{storage['type']} {storage['label']} @ slot{storage['slot']}"

def compare_storage_slots(sl1, sl2):
    """
    Comparing storage slot 1 and storage slot 2:
    sl1 is supposed to be the first implementation version or the proxy
    sl2 is supposed to be the second implem or the implementation
    """
    changes = 0
    for i in range(len(sl1['storage'])):
        if i > len(sl2['storage']):
            error(f"Removed in Storage1: {display_storage_data(sl1['storage'][i])}")
            changes += 1
            continue
        if sl2['storage'][i]['type'] != sl1['storage'][i]['type']:
            error(f"Type change (Storage1 vs Storage2)")
            error(f"Storage1 -> {display_storage_data(sl1['storage'][i])}")
            error(f"Storage2 -> {display_storage_data(sl2['storage'][i])}")
            changes += 1
            continue
        if sl2['storage'][i]['label'] != sl1['storage'][i]['label']:
            error(f"Label change (Storage1 vs Storage2)")
            error(f"Storage1 -> {display_storage_data(sl1['storage'][i])}")
            error(f"Storage2 -> {display_storage_data(sl2['storage'][i])}")
            changes += 1
            continue
    if changes == 0:
        good("No changes between the two contracts on storage (name or type)")
    if len(sl2['storage']) > len(sl1['storage']):
        for i in range(len(sl1['storage'])+1, len(sl2['storage'])):  
            error(f"Added in Storage2 -> {display_storage_data(sl2['storage'][i])}")
            continue


def get_structure_members(sU, name):
    """
    We can only get structure definition by using the source Unit (not the obj version)
    """
    struct_def = None
    for node in sU.children:
        if node.type == 'StructDefinition' and node.name == name:
            struct_def = node.members
            break
    return struct_def

def check_erc7201_storage(sc, binfo):
    """
    Still in dev ....
    Finds a ERC7201 struct and checks for collision with a new version of the contract
    This would work with any storage structure
    1/ check bytes32 declaration (storage location that follow the ERC7201 scheme 
        keccak256(abi.encode(uint256(keccak256("STORAGE_NAME")) - 1)) & ~bytes32(uint256(0xff))
    2/ func with asm block that uses this bytes32 constant
    3/ get return type
    4/ find structure declaration / members
    5/ same for other file and compare structure
    """
    sUO = get_source_unit_object(sc, binfo)
    ct = sUO.contracts[sc]

    erc7201_storages = {}
    for sv in ct.stateVars:
        if ct.stateVars[sv].typeName.name == 'bytes32':
            #code.interact(local=locals())
            b32_val = ct.stateVars[sv].expression.number
            erc7201_storages[b32_val] = {'name': sv}
   
    for f in ct.functions:
        # we look for functions with storage in their name and that are pure (does not change the state)
        # this is maybe too strict
        if "storage" in f or "Storage" in f and ct.functions[f].stateMutability == 'pure':
            node = ct.functions[f]._node
            for stat in node.body.statements:
                if stat.type == 'InLineAssemblyStatement' and stat.body.type == 'AssemblyBlock':
                    #build info json does not contain enough info
                    for erc7021_stor in erc7201_storages.keys():
                        if erc7201_storages[erc7021_stor]['name'] in str(stat.body.operations): #forgive me, this is ugly
                            if has_function_only_one_return_val:
                                struct_name = get_function_return_first_type(ct.functions[f])
                                erc7201_storages[erc7021_stor]['structure'] = {'name': struct_name, 'members':[]}
    
    sU = get_source_unit(get_contract_content(sc, binfo))
    for erc7021_stor in erc7201_storages.keys():
        struct_members = get_structure_members(sU, struct_name)
        if struct_members is not None:
            erc7201_storages[erc7021_stor]['structure']['members'] = struct_members
        else:
            #we have to research in all imported files :o  
            todo("search in all imports of the contract")
                                  
    print(erc7201_storages)
    #code.interact(local=locals())


def storage_collision_check(sc1, build_info_fp1, sc2, build_info_fp2):
    """
    Checks collision of storage between:
        - two versions of implementation
        - a proxy and an implementation
    Basically, if the storage variable has not the same type of the same label
        - it could collide between the two versions of two implementations
        - it could collide between the proxy and the implementation
    """
    info("[Storage collision]")
    binfo1 = json.loads(open(build_info_fp1, 'r').read())
    binfo2 = json.loads(open(build_info_fp2, 'r').read())

    storageLayout1 = get_contract_storage(sc1, binfo1)
    storageLayout2 = get_contract_storage(sc2, binfo2)

    if storageLayout1 == None and storageLayout2 == None:
        info("TODO IMPLEM FOR ERC7201")
        #check_erc7201_storage(sc1, binfo1)

    if storageLayout1 is None or storageLayout2 is None:
        error(f"One of the artefact files is not in the correct format")
        error(f"There is maybe no storage in one of the contracts!")
        error("How-to build contracts to have storageLayout")
        error(f"- with foundry")
        error("\tforge build --evm-version cancun --extra-output storageLayout")
        error(f"- with hardhat")
        error("\tIn solidity.settings:  outputSelection: { '*': { '*': ['storageLayout'] } },")
        error(f"It could also be that the contract uses ERC7201")
        return

    compare_storage_slots(storageLayout1, storageLayout2)


def function_clashing(sc1, build_info_fp1, sc2, build_info_fp2):
    """
    Checks for function clashing between proxy and implementation
    """
    fsig1 = get_functions_sigs_from_artefact(sc1, build_info_fp1)
    fsig2 = get_functions_sigs_from_artefact(sc2, build_info_fp2)

    sighash1 = {}
    sighash2 = {}
    for sig in fsig1:
        sighash1[compute_function_sighash(sig)] = sig
    for sig in fsig2:
        sighash2[compute_function_sighash(sig)] = sig
    
    for sighash in sighash1:
        if sighash in sighash2.keys():
            error(f"function clash with sighash -> 0x{sighash}")
            error(f"\t{sighash1[sighash]} == {sighash2[sighash]} ")

def display_slots(sl):
    if len(sl)==0:
        info("The contract has no storage variables")
    else:
        for storage in sl['storage']:
            info(f"\t{storage['type']} {storage['label']} @ slot{storage['slot']}")

def display_all_storage(name, fp):
    """
    Displays all storage data of the given artefact
    """
    binfo = json.loads(open(fp, 'r').read())
    storageLayout = get_contract_storage(name, binfo)
    
    if storageLayout is None:
        error(f"One of the artefact files is not in the correct format")
        error(f"- with foundry")
        error("\tforge build --evm-version cancun --extra-output storageLayout --build-info")
        error(f"- with hardhat")
        error("\tIn solidity.settings:  outputSelection: { '*': { '*': ['storageLayout'] } },")
        exit(1)
    info(f"[{name}] storage slots:")
    display_slots(storageLayout)


def get_contract_content_from_debug_info(name, debug_info):
    """
    Gets the content of a contract based on its name
    Approximative shit tbh and specific to foundry ...
    """
    debug_j = json.loads(debug_info)
    matching_fn = 0
    content = ""
    for fn in debug_j['input']['sources'].keys():
        if name in fn:
            if matching_fn == 0:
                matching_fn += 1
                content = debug_j['input']['sources'][fn]['content']
            else:
                error("More than one file matching the base contract name (inheritance file)")
                exit(1)
    return content

    


def get_contract_initfuncs(inheritanceMap={}, name="", binfo="", depth=0):
    """
    Visit the contract and builds an inheritanceMap obj that contains every contracts init funcs
    TODO: 
        - handle unchained (brings more complexity if called (parent contract init should be manually called aswell))
    """
    #print(f"[NAME] --------> {name} / depth = {depth} / inheritanceMap {list(inheritanceMap.keys())}")
    ct_content = get_contract_content(name, binfo)
    sU = parser.parse(ct_content, loc=True)
    for node in sU.children:
        #visiting contracts definition that are not interfaces
        if node.type == "ContractDefinition" and not is_contract_interface(node.name, binfo):
            contractName = node.name
            baseContracts = []
            content = {'init_funcs': {}, 'baseContracts': baseContracts, 'depth': depth}

            #Find all init-like funcs
            for sn in node.subNodes:
                if sn.type == 'FunctionDefinition' and not sn.isConstructor:
                    modifiers = sn.modifiers
                    isInitializer = False
                    if "init" in sn.name: # and "unchained" not in sn.name: #avoiding unchained
                        isInitializer = True
                    else:
                        for modif in modifiers:
                            if "init" in modif.name:
                                isInitializer = True
                                break
                    if isInitializer:
                        content['init_funcs'][sn.name] = sn #we should cut off shit from the sn obj (its overkill to store all that :/)
                        content['init_funcs'][sn.name]['invoked'] = 0
            inheritanceMap[contractName] = content

            #Visit all baseContracts (parents/inherited contracts) recursively
            for base in node.baseContracts:
                #we don't care about interfaces
                if(is_contract_interface(base.baseName.namePath, binfo)):
                    continue
                
                inheritanceMap[contractName]['baseContracts'].append(base.baseName.namePath)

                #contract already visited
                if base.baseName.namePath in inheritanceMap.keys():
                    continue

                #visiting inherited contract
                im = get_contract_initfuncs(inheritanceMap, base.baseName.namePath, binfo, depth=depth+1)
                inheritanceMap.update(im)
    return inheritanceMap


def check_all_initialize_functions_are_called(name, build_info_fp):
    """
    Checks that all initialize function are called in other initializers
    ex: initialize -> __RentrancyGuard_init() -> __Reentrancy_init_unchained()
    1. Get the contract definition
    2. For that definition get all baseContract (basically inheritances)
        - add dependency between contract + baseContract
        - loop through new baseContract until there is no more inheritances
    3. walk down (from most in depth contract towards upper contract)
        check that the initialize function is called (and not twice)

    TODO
        - add explanation for error
            - if never invoked -> it is maybe the round initializer function
            - if invoked more than once can be problematic -> explain why
    """
    binfo =  json.loads(open(build_info_fp, 'r').read())
    inheritanceMap = get_contract_initfuncs(name=name, binfo=binfo)
    print("-"*100)
    for ct_name in inheritanceMap.keys():
        function_calls = []
        print(f"[{ct_name}]")
        for func_name in inheritanceMap[ct_name]['init_funcs'].keys():
            print(f"\t{func_name}()")
            for statement in inheritanceMap[ct_name]['init_funcs'][func_name]['body']['statements']:
                if statement.type == 'ExpressionStatement' and statement.expression.type == 'FunctionCall':
                    if statement.expression.expression.type == 'Identifier':
                        function_calls.append(statement.expression.expression.name)
                        print(f"\t\tinvokes -> {statement.expression.expression.name}")
                    elif statement.expression.expression.type == 'MemberAccess':
                        function_calls.append(statement.expression.expression.memberName)
                        print(f"\t\tinvokes -> {statement.expression.expression.memberName}")
                    else:
                        error("FunctionCall not handled")
                        code.interact(local=locals())
                     
        #update function status that have been called
        for func_call in function_calls:
            for ct_name in inheritanceMap.keys():
                if func_call in inheritanceMap[ct_name]['init_funcs'].keys():
                    inheritanceMap[ct_name]['init_funcs'][func_call]['invoked'] += 1
    
    for ct_name in inheritanceMap.keys():
        for func_name in inheritanceMap[ct_name]['init_funcs'].keys():
            if  inheritanceMap[ct_name]['init_funcs'][func_name]['invoked'] == 0:
                error(f"[{ct_name}] -> {func_name}() is never invoked")
            elif inheritanceMap[ct_name]['init_funcs'][func_name]['invoked'] > 1:
                error(f"[{ct_name}] -> {func_name}() is invoked more than once")
                


def has_dangerous_opcode(sn):
    """
    Check function body
        - no selfdestruct()
        - no delegatecall()
        - no asm !
    """
    banned = ["delegatecall", "selfdestruct", "assembly block"]
    names = []
    #sometimes there is no body to the statement...
    if len(sn.body) == 0:
        return names

    for statement in sn.body.statements:
        name = ""
        if 'InLineAssemblyStatement' in statement.type:
            name = "assembly block"
        elif statement.type == 'ExpressionStatement' and statement.expression.type == 'FunctionCall':
            if type(statement.expression.expression) is list:
                if statement.expression.expression[0].type == 'MemberAccess':
                    name =  statement.expression.expression[0].memberName
            elif statement.expression.expression.type == 'Identifier':
                name =  statement.expression.expression.name
            elif statement.expression.expression.type == 'MemberAccess':
                name =  statement.expression.expression.memberName
            else:
                todo("not hanlded statement type!")
                code.interact(local=locals())
        if name in banned:
            name += f"@L{statement.loc['start']['line']}"
            names.append(name)
    return names

def check_if_contract_has_dangerous_opcodes(name, binfo="", visited_contracts=[], depth=0):
    """
    Checks for opcodes that could lead to proxy destruction:
        - delegatecall() to controlled address
        - selfdestruct()
        - assembly blocks ?
    
    TODO:
        - only look for functions in inherited contracts that are called by the contract we are analyzing ?
    """
    ct_content = get_contract_content(name, binfo)
    sU = parser.parse(ct_content, loc=True)
    for node in sU.children:
        if node.type == "ContractDefinition" and not is_contract_interface(node.name, binfo):
            if node.name in visited_contracts:
                print(f"{node.name} is already processed")
                continue
            visited_contracts.append(node.name)
            print(f"{"\t"*(depth)}[{node.name}]")
            for sn in node.subNodes:
                #print(sn.type)
                if sn.type == 'FunctionDefinition' and not sn.isConstructor:
                    dangerous_func = has_dangerous_opcode(sn)
                    if len(dangerous_func) > 0:
                        error(f"{"\t"*(depth)} {sn.name} makes call(s) to {" / ".join(dangerous_func)}")
                        todo("verify that this call cannot lead to destruction of the proxy contrat")
            
            for base in node.baseContracts:
                if is_contract_interface(base.baseName.namePath, binfo):
                    continue
                visited_contracts = check_if_contract_has_dangerous_opcodes(base.baseName.namePath, binfo, visited_contracts)
    return visited_contracts
     

def check_for_dangerous_opcodes(name, build_info_fp):
    binfo =  json.loads(open(build_info_fp, 'r').read())
    check_if_contract_has_dangerous_opcodes(name, binfo)   


def UUPSChecks(name, build_info_fp):
    binfo = json.loads(open(build_info_fp, 'r').read())
    sUO = get_source_unit_object(name, binfo)

    check_constructor(name, sUO.contracts[name])
    check_initializers(sUO.contracts[name])
    upgrade_access_control(sUO.contracts[name])
    check_for_immutables(sUO.contracts[name])



arg_parser = argparse.ArgumentParser(description="Upgrade Guardian (tool to facilitate upgradeability checks on smart contracts)")
arg_parser.add_argument("--sc1", "--contract-name1", action="store", dest="sc1", help="Contract 1 name to analyze", required=True)
arg_parser.add_argument("--sc2", "--contract-name2", action="store", dest="sc2", help="Contract 2 name to analyze")


arg_parser.add_argument("--dbg1", "--build-info1", action="store", dest='fp_binfo1', help="File path of the debug info of the 1st smart contract", required=True)
arg_parser.add_argument("--dbg2", "--build-info2", action="store", dest='fp_binfo2', help="File path of the debug info of the 2nd smart contract")

arg_parser.add_argument("--ds", "--display-storage", action="store_true", dest='display_storage', help="Display storage of submitted contract")


args = arg_parser.parse_args()


UUPSChecks(args.sc1, args.fp_binfo1)

check_all_initialize_functions_are_called(args.sc1, args.fp_binfo1)
check_for_dangerous_opcodes(args.sc1, args.fp_binfo1)

"""
When we have two contracts then do the diffing
- storage collision check
- function classhing check
"""
if args.sc2 != None and args.fp_binfo2 != None:
    storage_collision_check(args.sc1, args.fp_binfo1, args.sc2, args.fp_binfo2)
    function_clashing(args.sc1, args.fp_binfo1, args.sc2, args.fp_binfo2)



"""
display storage when source + storageLayout
"""
if args.display_storage:
    if args.fp_binfo1:
        display_all_storage(args.sc1, args.fp_binfo1)
    if args.fp_binfo2:
        display_all_storage(args.sc2, args.fp_binfo2)
