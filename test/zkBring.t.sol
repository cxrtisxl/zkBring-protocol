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
import {TestUtils} from "./TestUtils.sol";
import {zkBringDropByVerification} from "../src/drop_factory/zkBringDropByVerification.sol";
import {Token} from "../src/mock/Token.sol";

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
    Token private token;
    Token private bringToken;
    zkBringDropByVerification private drop;

    function setUp() public {
        (tlsnVerifier.addr, tlsnVerifier.privateKey) = makeAddrAndKey("TLSN-verifier");

        semaphoreVerifier = new SemaphoreVerifier();
        semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));
        registry = new zkBringRegistry(ISemaphore(address(semaphore)), tlsnVerifier.addr);
        bringToken = new Token("Bring", "BRING", address(this), 10000);
        token = new Token("Testo", "TESTO", address(this), 10000);
    }

    // @notice verifies user data, generates commitment and adds it to Registry
    function verify(
        address commitmentSender_,
        uint256 verificationId_,
        bytes32 idHash_,
        uint256 semaphoreIdentityCommitment
    ) public {
        IRegistry.TLSNVerifierMessage memory verifierMessage = IRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: verificationId_,
            idHash: idHash_, // Random identity
            semaphoreIdentityCommitment: semaphoreIdentityCommitment
        });

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifier.privateKey,
            keccak256(abi.encode(verifierMessage)).toEthSignedMessageHash()
        );

        // Joining group
        vm.prank(commitmentSender_);
        registry.joinGroup(verifierMessage, v, r, s);
    }

    function testVerification() public {
        uint256 verificationId = vm.randomUint();
        registry.newVerification(verificationId, 10); // Creating a new Verefication
        verify(
            vm.randomAddress(), // Calling from a random address (drop contract / DAO voting contract etc.)
            verificationId,
            keccak256(vm.randomBytes(32)),
            TestUtils.semaphoreCommitment(vm.randomUint())
        );
    }

    function testValidation() public {
        uint256 verificationId = vm.randomUint();
        registry.newVerification(verificationId, 10); // Creating a new Verefication

        uint256 commitmentKey = vm.randomUint();
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = TestUtils.semaphoreCommitment(commitmentKey);

        address sender = vm.randomAddress();

        verify(
            sender, // Calling from a random address (Relayer)
            verificationId,
            keccak256(vm.randomBytes(32)),
            commitments[0]
        );

        uint256 scope = uint256(keccak256(abi.encode(sender, 0)));

        (
            uint256 merkleTreeDepth,
            uint256 merkleTreeRoot,
            uint256 nullifier,
            uint256 message,
            uint256[8] memory points
        ) = TestUtils.semaphoreProof(
            commitmentKey,
            scope,
            commitments
        );

        IRegistry.VerificationProof memory proof = IRegistry.VerificationProof(
            verificationId,
            ISemaphore.SemaphoreProof(
                merkleTreeDepth,
                merkleTreeRoot,
                nullifier,
                message,
                scope,
                points
            )
        );
        vm.prank(sender);
        registry.validateProof(0, proof);
    }

    function testClaim() public {
        address sender = vm.randomAddress(); // e.g. Relayer or "someone"
        uint256 verificationId = vm.randomUint();
        drop = new zkBringDropByVerification(
            verificationId,
            registry,
            address(sender),
            token,
            10,
            1000,
            block.timestamp * 2,
            "",
            bringToken
        );
        token.transfer(address(drop), 10000);
        registry.newVerification(verificationId, 10); // Creating a new Verefication

        uint256 commitmentKey = vm.randomUint();
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = TestUtils.semaphoreCommitment(commitmentKey);

        verify(
            sender, // Calling from a random address (Relayer)
            verificationId,
            keccak256(vm.randomBytes(32)),
            commitments[0]
        );

        uint256 scope = uint256(keccak256(abi.encode(address(drop), 0)));

        (
            uint256 merkleTreeDepth,
            uint256 merkleTreeRoot,
            uint256 nullifier,
            uint256 message,
            uint256[8] memory points
        ) = TestUtils.semaphoreProof(
            commitmentKey,
            scope,
            commitments
        );

        IRegistry.VerificationProof memory proof = IRegistry.VerificationProof(
            verificationId,
            ISemaphore.SemaphoreProof(
                merkleTreeDepth,
                merkleTreeRoot,
                nullifier,
                message,
                scope,
                points
            )
        );
        address recipient = vm.randomAddress();
        drop.claim(proof, recipient);
        assertEq(token.balanceOf(recipient), 10);
    }
}
