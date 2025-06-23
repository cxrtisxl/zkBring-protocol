// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console} from "forge-std/Script.sol";
import {ISemaphoreVerifier} from "semaphore-protocol/interfaces/ISemaphoreVerifier.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {SemaphoreVerifier} from "semaphore-protocol/base/SemaphoreVerifier.sol";
import {Semaphore} from "semaphore-protocol/Semaphore.sol";
import {zkBringRegistry} from "../src/registry/zkBringRegistry.sol";

contract DeployDev is Script {
    function setUp() public {}
    function run() public {
        // TLSN Verifier private key
        // 0x7FA50A02193219D0625C2831908477D3568E5BEECA9AABE34381506A2431AFDE
        address tlsnVerifierAddress = 0x3c50f7055D804b51e506Bc1EA7D082cB1548376C;
        SemaphoreVerifier semaphoreVerifier = new SemaphoreVerifier();
        Semaphore semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));
        zkBringRegistry registry = new zkBringRegistry(ISemaphore(address(semaphore)), tlsnVerifierAddress);

        console.log("Verifier:", address(semaphoreVerifier));
        console.log("Semaphore:", address(semaphore));
        console.log("Registry:", address(registry));
    }
}
