// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {SemiModularAccount7702} from "../src/account/SemiModularAccount7702.sol";

contract DeploySMA7702Script is Script {
    IEntryPoint public ep07 = IEntryPoint(payable(0x0000000071727De22E5E9d8BAf0edAc6f37da032));

    function run() public {
        vm.broadcast();
        SemiModularAccount7702 accountImpl = new SemiModularAccount7702{salt: 0}(ep07);

        console.log("SemiModularAccount7702 deployed at:");
        console.logAddress(address(accountImpl));
    }
}
