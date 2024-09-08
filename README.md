# UpGuardian


## Installation

- Install the following fork of the main `solidity_parser` repo. It supports `immutable` keyword:

https://github.com/Caglankaan/python-solidity-parser

```bash
pip3 installl -r requirements.txt
```


## URLs / Ressources
- python wrapper of antlr4 solidity language parsing
https://github.com/Consensys/python-solidity-parser

- fork ahead supporting immutables
https://github.com/Caglankaan/python-solidity-parser
```
pip3 install .
```

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

## What is it ?
- An helper for auditors to check upgradeability vulnerabilities (automatic checks and reminders);
- A monitoring tool to verify that new deployed contracts wont affect smart contract's security


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

### Tip: getting storageLayout depending on the dev environement

#### Forge / Foundry
forge build --evm-version cancun --extra-output storageLayout --build-info

--> build-info/x.json contains all sources

- example json content
```json
"storageLayout":{"storage":[{"astId":49271,"contract":"src/UUPS_selfdestruct/SimpleToken.sol:SimpleToken","label":"lol","offset":0,"slot":"0","type":"t_address"}],"types":{"t_address":{"encoding":"inplace","label":"address","numberOfBytes":"20"}}}
```

#### Hardhat
npx hardhat compile -> In solidity.settings : outputSelection: { '*': { '*': ['storageLayout'] } },





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
