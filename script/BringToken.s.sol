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
import {CredentialRegistry} from "../src/registry/CredentialRegistry.sol";

contract DeployDev is Script {
    function run() public {
        // TLSN Verifier private key
        // 0x7FA50A02193219D0625C2831908477D3568E5BEECA9AABE34381506A2431AFDE
        address tlsnVerifierAddress = 0x3c50f7055D804b51e506Bc1EA7D082cB1548376C;

        address deployer = vm.addr(vm.envUint("PRIVATE_KEY"));

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        Token bringToken = new Token("Bring", "BRING", deployer, 10**32);
        vm.stopBroadcast();

        console.log("Bring Token:", address(bringToken));
    }
}
