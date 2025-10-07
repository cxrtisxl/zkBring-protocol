// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "../src/drop/BringDropByVerification.sol";
import "../src/drop/BringDropByScore.sol";
import {ICredentialRegistry} from "../src/registry/ICredentialRegistry.sol";
import {ISemaphoreVerifier} from "semaphore-protocol/interfaces/ISemaphoreVerifier.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {Script, console} from "forge-std/Script.sol";
import {SemaphoreVerifier} from "semaphore-protocol/base/SemaphoreVerifier.sol";
import {Semaphore} from "semaphore-protocol/Semaphore.sol";
import {Token} from "../src/mock/Token.sol";
import {CredentialRegistry, ICredentialRegistry} from "../src/registry/CredentialRegistry.sol";

contract Register  is Script {
    function run() public {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
            CredentialRegistry registry;
            if (vm.envAddress('CREDENTIAL_REGISTRY_ADDRESS') != address(0)) {
                registry = CredentialRegistry(vm.envAddress('CREDENTIAL_REGISTRY_ADDRESS'));
            } else {
                revert("CREDENTIAL_REGISTRY_ADDRESS should be provided");
            }

            registry.createCredentialGroup(99, 10);
            registry.createCredentialGroup(1, 10);
            registry.createCredentialGroup(2, 20);
            registry.createCredentialGroup(3, 10);
            registry.createCredentialGroup(4, 5);
            registry.createCredentialGroup(5, 10);
        vm.stopBroadcast();

        (,uint256 semaphoreGroupId,) = registry.credentialGroups(99);
        console.log("99:", semaphoreGroupId);
        (,semaphoreGroupId,) = registry.credentialGroups(1);
        console.log("1:", semaphoreGroupId);
        (,semaphoreGroupId,) = registry.credentialGroups(2);
        console.log("2:", semaphoreGroupId);
        (,semaphoreGroupId,) = registry.credentialGroups(3);
        console.log("3:", semaphoreGroupId);
        (,semaphoreGroupId,) = registry.credentialGroups(4);
        console.log("4:", semaphoreGroupId);
        (,semaphoreGroupId,) = registry.credentialGroups(5);
        console.log("5:", semaphoreGroupId);
    }
}