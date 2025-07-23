// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "../src/id_card/IdCard.sol";
import {ICredentialRegistry} from "../src/registry/ICredentialRegistry.sol";
import {Script, console} from "forge-std/Script.sol";

contract DeployIdCard is Script {
    function run() public {
        // Assume registry is already deployed - get from environment or use hardcoded address
        address registryAddress = vm.envOr("CREDENTIAL_REGISTRY_ADDRESS", address(0));
        
        require(registryAddress != address(0), "CREDENTIAL_REGISTRY_ADDRESS must be set");
        
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Deploy IdCard contract
        IdCard idCard = new IdCard(ICredentialRegistry(registryAddress));
        
        vm.stopBroadcast();
        
        console.log("=== IdCard Deployment ===");
        console.log("Deployer:", deployer);
        console.log("Registry:", registryAddress);
        console.log("IdCard:", address(idCard));
        console.log("Owner:", idCard.owner());
        console.log("Stopped:", idCard.stopped());
    }
}

contract DeployIdCardWithRegistry is Script {
    function run() public {
        // TLSN Verifier private key from existing script
        // 0x7FA50A02193219D0625C2831908477D3568E5BEECA9AABE34381506A2431AFDE
        address tlsnVerifierAddress = 0x3c50f7055D804b51e506Bc1EA7D082cB1548376C;
        
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        vm.startBroadcast(deployerPrivateKey);

        Semaphore semaphore;
        if (vm.envAddress('SEMAPHORE_ADDRESS') == address(0)) {
            SemaphoreVerifier semaphoreVerifier = new SemaphoreVerifier();
            semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));
        } else {
            semaphore = Semaphore(vm.envAddress('SEMAPHORE_ADDRESS'));
        }
        
        // Deploy CredentialRegistry
        CredentialRegistry registry = new CredentialRegistry(
            ISemaphore(address(semaphore)), 
            tlsnVerifierAddress
        );
        
        // Create credential groups that IdCard expects
        registry.createCredentialGroup(1, 10); // X account owner
        registry.createCredentialGroup(2, 20); // Has Uber rides
        
        // Deploy IdCard contract
        IdCard idCard = new IdCard(ICredentialRegistry(address(registry)));
        
        vm.stopBroadcast();
        
        console.log("=== Full IdCard Deployment ===");
        console.log("Deployer:", deployer);
        console.log("TLSN Verifier:", tlsnVerifierAddress);
        console.log("Semaphore:", address(semaphore));
        console.log("Registry:", address(registry));
        console.log("IdCard:", address(idCard));
        console.log("Owner:", idCard.owner());
        console.log("Stopped:", idCard.stopped());
        console.log("");
        console.log("Credential Groups Created:");
        console.log("  Group 1 (X account owner): Score 100");
        console.log("  Group 2 (Has Uber rides): Score 200");
    }
}

// Import necessary contracts for the full deployment
import {SemaphoreVerifier} from "semaphore-protocol/base/SemaphoreVerifier.sol";
import {Semaphore} from "semaphore-protocol/Semaphore.sol";
import {ISemaphoreVerifier} from "semaphore-protocol/interfaces/ISemaphoreVerifier.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {CredentialRegistry} from "../src/registry/CredentialRegistry.sol";