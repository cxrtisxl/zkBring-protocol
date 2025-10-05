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

contract DeployDevDropByScore is Script {
    function run() public {
        address deployer = vm.addr(vm.envUint("PRIVATE_KEY"));
        vm.startBroadcast(deployer);
            Token token = new Token(
                "Testo",
                "TESTO",
                deployer,
                10**32
            );
            Token bringToken = new Token(
                "Bring",
                "BRING",
                deployer,
                10**32
            );
            BringDropByScore drop = new BringDropByScore(
                10,
                ICredentialRegistry(0x71a1D4f105aBccC82565fA6969A4685aF92c99C8),
                deployer,
                IERC20(address(token)),
                10**19,
                10**13,
                block.timestamp * 2,
                "",
                bringToken
            );
            token.transfer(address(drop), 10**32);
        vm.stopBroadcast();

        console.log("Mock Token:", address(token));
        console.log("Bring Token:", address(bringToken));
        console.log("Drop:", address(drop));
    }
}

contract DeployDev is Script {
    function run() public {
        // TLSN Verifier private key
        // 0x7FA50A02193219D0625C2831908477D3568E5BEECA9AABE34381506A2431AFDE
        address tlsnVerifierAddress = 0x3c50f7055D804b51e506Bc1EA7D082cB1548376C;

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
            SemaphoreVerifier semaphoreVerifier;
            Semaphore semaphore;
            if (vm.envAddress('SEMAPHORE_ADDRESS') != address(0)) {
                semaphore = Semaphore(vm.envAddress('SEMAPHORE_ADDRESS'));
            } else {
                semaphoreVerifier = new SemaphoreVerifier();
                semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));
            }
            CredentialRegistry registry = new CredentialRegistry(ISemaphore(address(semaphore)), tlsnVerifierAddress);
            Token token = new Token("Testo", "TESTO", msg.sender, 10**32);
            Token bringToken = new Token("Bring", "BRING", msg.sender, 10**32);
        vm.stopBroadcast();

        console.log("Verifier:", address(semaphoreVerifier));
        console.log("Semaphore:", address(semaphore));
        console.log("Registry:", address(registry));
        console.log("Mock Token:", address(token));
        console.log("Bring Token:", address(bringToken));
    }
}

contract Deploy  is Script {
    function run() public {
        // TLSN Verifier private key
        // 0x7FA50A02193219D0625C2831908477D3568E5BEECA9AABE34381506A2431AFDE
        address tlsnVerifierAddress = 0x3c50f7055D804b51e506Bc1EA7D082cB1548376C;

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        Semaphore semaphore;
        if (vm.envAddress('SEMAPHORE_ADDRESS') != address(0)) {
            semaphore = Semaphore(vm.envAddress('SEMAPHORE_ADDRESS'));
        } else {
            revert("SEMAPHORE_ADDRESS should be provided");
        }
        CredentialRegistry registry = new CredentialRegistry(ISemaphore(address(semaphore)), tlsnVerifierAddress);
        vm.stopBroadcast();

        console.log("Semaphore:", address(semaphore));
        console.log("Registry:", address(registry));
    }
}
