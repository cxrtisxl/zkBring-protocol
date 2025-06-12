// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {ISemaphoreVerifier} from "semaphore-protocol/interfaces/ISemaphoreVerifier.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {SemaphoreVerifier} from "semaphore-protocol/base/SemaphoreVerifier.sol";
import {Semaphore} from "semaphore-protocol/Semaphore.sol";
import {zkBringRegistry} from "../src/registry/zkBringRegistry.sol";
import {IzkBringRegistry as IRegistry} from "../src/registry/IzkBringRegistry.sol";
import {Test, console} from "forge-std/Test.sol";
import {zkBringDropFactory} from "../src/drop_factory/zkBringDropFactory.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

struct TLSNVerifier {
    uint256 privateKey;
    address addr;
}

contract zkBringTest is Test {
    using ECDSA for bytes32;

    SemaphoreVerifier private semaphoreVerifier;
    Semaphore private semaphore;

    zkBringRegistry private registry;
    zkBringDropFactory private dropFactory;
    TLSNVerifier private tlsnVerifier;

    function setUp() public {
        (tlsnVerifier.addr, tlsnVerifier.privateKey) = makeAddrAndKey("TLSN-verifier");

        semaphoreVerifier = new SemaphoreVerifier();
        semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));
        registry = new zkBringRegistry(ISemaphore(address(semaphore)), tlsnVerifier.addr);
        registry.newVerification(1);
        // (uint8 v, bytes32 r, bytes32 s) = vm.sign(verifier.privateKey, hash);
    }

    function getCommitment(uint256 commitmentKey) public {
        string[] memory inputs = new string[](3);
        inputs[0] = "node";
        inputs[1] = "semaphore-js/commitment.mjs";
        inputs[2] = vm.toString(bytes32(commitmentKey));
        bytes memory res = vm.ffi(inputs);
        string memory output = abi.decode(res, (string));
        console.log(output);
    }

    function getProof() public {
    }

    function testCommitment() public {
        (, uint256 privateKey) = makeAddrAndKey("someone");
        getCommitment(privateKey);
    }

    function testVerification() public {
        // Here we generate a mock message for Verifier to sign
        IRegistry.TLSNVerifierMessage memory verifierMessage = IRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: 1,
            idHash: keccak256("alice"),
            semaphoreIdentityCommitment: 1
        });
        bytes32 TLSNVerifierSignedMessageHash = keccak256(
            abi.encode(verifierMessage)
        ).toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(tlsnVerifier.privateKey, TLSNVerifierSignedMessageHash);

        // Joining group
        vm.prank(makeAddr("cxrtisxl"));
        registry.joinGroup(verifierMessage, v, r, s);
    }
}
