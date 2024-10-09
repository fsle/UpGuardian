# UpGuardian

## What is it ?
- An helper for auditors to check upgradeability vulnerabilities (automatic checks and reminders)
- A monitoring tool to verify that new deployed contracts wont affect smart contract's security


## Installation

- Create a virtualenv (to not mess up your whole python setup)
- Install python dependencies 
- Clone, patch and install a `solidity_parser` fork repo (it supports `immutable` keyword and a patch reduces errors verbosity)

```bash
mkvirtualenv upg
pip3 install -r requirements.txt
git clone https://github.com/Caglankaan/python-solidity-parser
cd python-solidity-parser/
git checkout ffde787b63c02f7b107729ce80b1d243febf8531
git apply ../../less_verbose.patch
pip3 install .
```

## Usage requirement

The tool needs two types of argument:
- the contract name
- the build-info file


The build info file is created during the project's compilation and is the angular file used in the tool. Here are a few tips to have storage details depending on the dev env.

#### Forge / Foundry
```
forge build --evm-version cancun --extra-output storageLayout --build-info
```

#### Hardhat
-> In solidity.settings : outputSelection: { '*': { '*': ['storageLayout'] } },
```
npx hardhat compile 
```

- example json content
```json
"storageLayout":{"storage":[{"astId":49271,"contract":"src/UUPS_selfdestruct/SimpleToken.sol:SimpleToken","label":"lol","offset":0,"slot":"0","type":"t_address"}],"types":{"t_address":{"encoding":"inplace","label":"address","numberOfBytes":"20"}}}
```

## Usage

The tool can currently be use in two mode:
- standalone contract: that checks upgradeability related risks on the specified contract
- dual contract: standalone mode with more checks (function and storage clashing between the two contracts) 
```
python3 UpG.py --sc1 <contractName1> --dbg1 <path-to-debug-file1> --sc2 <contractName2> --dbg2 <path-to-debug-file2>
```

## URLs / Ressources
- python wrapper of antlr4 solidity language parsing
https://github.com/Consensys/python-solidity-parser

- fork ahead supporting immutables
https://github.com/Caglankaan/python-solidity-parser

- solidity doc to gen storageLayout when compiling
https://docs.soliditylang.org/en/latest/using-the-compiler.html#input-description

- json storage layout format
https://docs.soliditylang.org/en/v0.8.15/internals/layout_in_storage.html#json-output

- oz upgradeable contract vulnerability (initialize implementation):
https://forum.openzeppelin.com/t/security-advisory-initialize-uups-implementation-contracts/15301


- Namespaced Storage Layout (ERC-7201) / applied since openzepellin 5.0:
https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable#namespaced-storage-layout

## Proxies
- TTP (Transparent Proxy Pattern):
    - proxy contains the upgrade logic `upgradeTo()`
- UUPS: 
    - implementation contains the upgrade logic
    - upgrade = call proxy -> to implem -> changes new implem
    - update many proxies = update all of them
- BeaconProxy:
    - proxy -> BeaconProxy -> Implementation
    - update = call proxy -> asks Beacon's which address of the implem -> Implem identified
    - upgrade many proxy = one call cheap


Types of proxy:
- basic delegatecall (0x3660006000376110006000366000732157a7894439191e520825fe9399ab8655e0f7085af41558576110006000f3)
- TTP (fallback acts differently depending on msg.sender (admin)) + has upgrade logic -> should have access control
- UUPS (contains an initialize function, delegates upgrade to implem contract)
- metamorphic contracts (selfdestruct + redeploy)
- diamond proxy (diamond, facet, loupe)




## Helper

### Checks todo

- Uninitialized implementation
-> constructor should `_disableInitializers()`
if not implem could get init by attacker (changing its own storage); then upgradeToAndCall would be callable from the implem (and new owner); delegate call to selfdestruct
https://github.com/Picodes/4naly3er/blob/8a9d1ebb7d362bc94f036fa9123d0977c6cb7436/src/issues/L/disableInitImpl.ts

https://medium.com/immunefi/harvest-finance-uninitialized-proxies-bug-fix-postmortem-ea5c0f7af96b

- Missing __gap with upgradeable contracts
-> should contain __gap in storage variable for new variables for upcoming versions
https://github.com/Picodes/4naly3er/blob/8a9d1ebb7d362bc94f036fa9123d0977c6cb7436/src/issues/L/upgradeableMissingGap.ts#L7


- Unsafe proxy pattern
-> should use EIP1967 to avoid storage collision with used variable in contract
`keccak256('eip1967.proxy.implementation') - 1`
https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies


- Usage of immutable with proxy contracts
-> Upgradeable contracts have no constructors but initializers, immutable cannot be handled with them
-> Immutables values are stored in the bytecode, so a variable instantiated as immutable would result in all proxies pointing to the same value (in bytecode) rather than the proxy pointing to the variable in it's own sotrage
https://docs.openzeppelin.com/upgrades-plugins/1.x/faq#why-cant-i-use-immutable-variables

- Usage of delegatecall and selfdestruct in implementation
-> could destroy/mess with the proxy contract; it must be manually reviewed (controlled destination address, accessible for anyone, etc.)



- unintialized implem (__disableInitializers)
- no __gap with upgradeable contracts
- unsafe proxy pattern (storage slot used for implem address)
- immutable with proxy contracts
- delagatecall + selfdestruct opcodes in implementations

- proxy authentication (to upgrade / initialize)
- function selector clash (check selector from proxy + contract)
    - if proxy has same selector than contract (it could hook the call)

### Monitor
- Updating storage size of a contract between two updates
-> The proper storage __gap size in the new version of the contract should be storage variables + gap size 


- monitor new update
    - watch storage
    - proxy authentication

    - init chains
    - ERC165 inheritance ?
    - fallback of delegatecalls()
    - uninitialized state variable





Modifier:
@openzeppelin-contracts/proxy/utils/Initializable.sol
- `initializer`modifier : protected initializer function that can be invoked at most once
    - _initializing
    - _initialized
- `onlyInitializing` modifier: functions can be used to initialize parent contracts.
- 
can be invoked at most once in its scope
- only




python3 UpG.py tests_foundry/src/UUPS_selfdestruct/SimpleToken.sol tests_foundry/out/SimpleToken.sol/SimpleToken.json tests_hardhat/artifacts/contracts/UUPS_selfdestruct/SimpleToken.sol/SimpleToken.dbg.json
