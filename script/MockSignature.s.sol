// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;
import {Script, console} from "forge-std/Script.sol";
import { IzkBringRegistry as IRegistry } from "../src/registry/IzkBringRegistry.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

contract Generate is Script {
    using ECDSA for bytes32;

    function run() public {
        IRegistry.TLSNVerifierMessage memory verifierMessage = IRegistry.TLSNVerifierMessage({
            registry: vm.envAddress("REGISTRY"),
            verificationId: vm.envUint("VERIFICATION_ID"),
            idHash: vm.envBytes32("ID_HASH"),
            semaphoreIdentityCommitment: vm.envUint("COMMITMENT")
        });

        bytes32 message = keccak256(abi.encode(verifierMessage)).toEthSignedMessageHash();

        console.logBytes32(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            vm.envUint("SIGNER_PK"),
            keccak256(abi.encode(verifierMessage)).toEthSignedMessageHash()
        );

        console.log(
            string.concat("Registry:\t", vm.toString(verifierMessage.registry))
        );
        console.log(
            string.concat("Ver. Id:\t", vm.toString(verifierMessage.verificationId))
        );
        console.log(
            string.concat("IdHash:\t", vm.toString(verifierMessage.idHash))
        );
        console.log(
            string.concat("Commitment:\t", vm.envString("COMMITMENT"))
        );
        console.log(
            string.concat("Signature:\t",
                vm.toString(abi.encodePacked(r, s, v))
            )
        );
    }
}
