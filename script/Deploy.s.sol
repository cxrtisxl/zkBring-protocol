// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "../src/drop/BringDropByVerification.sol";
import {ISemaphoreVerifier} from "semaphore-protocol/interfaces/ISemaphoreVerifier.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {Script, console} from "forge-std/Script.sol";
import {SemaphoreVerifier} from "semaphore-protocol/base/SemaphoreVerifier.sol";
import {Semaphore} from "semaphore-protocol/Semaphore.sol";
import {Token} from "../src/mock/Token.sol";
import {BringRegistry} from "../src/registry/BringRegistry.sol";

contract DeployDev is Script {
    function setUp() public {}
    function run() public {
        // TLSN Verifier private key
        // 0x7FA50A02193219D0625C2831908477D3568E5BEECA9AABE34381506A2431AFDE
        address tlsnVerifierAddress = 0x3c50f7055D804b51e506Bc1EA7D082cB1548376C;
        uint256 verificationId = 1;

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
            SemaphoreVerifier semaphoreVerifier = new SemaphoreVerifier();

            Semaphore semaphore;
            if (vm.envAddress('SEMAPHORE_ADDRESS') == address(0)) {
                semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));
            } else {
                semaphore = Semaphore(vm.envAddress('SEMAPHORE_ADDRESS'));
            }

            BringRegistry registry = new BringRegistry(ISemaphore(address(semaphore)), tlsnVerifierAddress);
            Token token = new Token("Testo", "TESTO", msg.sender, 10**32);
            Token bringToken = new Token("Bring", "BRING", msg.sender, 10**32);

            registry.newVerification(verificationId, 10);
            BringDropByVerification drop = new BringDropByVerification(
                verificationId,
                registry,
                msg.sender,
                token,
                10**19,
                10**13,
                block.timestamp * 2,
                "",
                bringToken
            );
            token.transfer(address(drop), 10**32);
        vm.stopBroadcast();

        console.log("Verifier:", address(semaphoreVerifier));
        console.log("Semaphore:", address(semaphore));
        console.log("Registry:", address(registry));
        console.log("Mock Token:", address(token));
        console.log("Bring Token:", address(bringToken));
        console.log("Drop:", address(drop));
    }
}
