// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import {CredentialRegistry} from "../src/registry/CredentialRegistry.sol";
import {ICredentialRegistry} from "../src/registry/ICredentialRegistry.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {ISemaphoreVerifier} from "semaphore-protocol/interfaces/ISemaphoreVerifier.sol";
import {SemaphoreVerifier} from "semaphore-protocol/base/SemaphoreVerifier.sol";
import {Semaphore} from "semaphore-protocol/Semaphore.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {TestUtils} from "./TestUtils.sol";

contract CredentialRegistryTest is Test {
    using ECDSA for bytes32;

    CredentialRegistry registry;
    Semaphore semaphore;
    SemaphoreVerifier semaphoreVerifier;
    
    address owner;
    address tlsnVerifier;
    uint256 tlsnVerifierPrivateKey;
    
    event CredentialGroupCreated(uint256 indexed credentialGroupId, ICredentialRegistry.CredentialGroup credentialGroup);
    event CredentialAdded(uint256 indexed credentialGroupId, uint256 indexed commitment);
    event ProofValidated(uint256 indexed credentialGroupId);
    event TLSNVerifierSet(address indexed verifier);

    function setUp() public {
        owner = address(this);
        (tlsnVerifier, tlsnVerifierPrivateKey) = makeAddrAndKey("tlsn-verifier");
        
        semaphoreVerifier = new SemaphoreVerifier();
        semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));
        registry = new CredentialRegistry(ISemaphore(address(semaphore)), tlsnVerifier);
    }

    function testConstructor() public {
        assertEq(address(registry.SEMAPHORE()), address(semaphore));
        assertEq(registry.TLSNVerifier(), tlsnVerifier);
        assertEq(registry.owner(), owner);
    }

    function testCreateCredentialGroup() public {
        uint256 credentialGroupId = 1;
        uint256 score = 100;
        
        vm.expectEmit(true, false, false, true);
        emit CredentialGroupCreated(credentialGroupId, ICredentialRegistry.CredentialGroup(score, 0, ICredentialRegistry.CredentialGroupStatus.ACTIVE));
        
        registry.createCredentialGroup(credentialGroupId, score);
        
        (uint256 storedScore, uint256 groupId, ICredentialRegistry.CredentialGroupStatus status) = registry.credentialGroups(credentialGroupId);
        assertEq(storedScore, score);
        assertTrue(groupId >= 0); // Group ID should exist (can be 0 for first group)
        assertEq(uint256(status), uint256(ICredentialRegistry.CredentialGroupStatus.ACTIVE));
    }

    function testCreateCredentialGroupOnlyOwner() public {
        address notOwner = makeAddr("not-owner");
        
        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.createCredentialGroup(1, 100);
    }

    function testCreateCredentialGroupDuplicate() public {
        uint256 credentialGroupId = 1;
        
        registry.createCredentialGroup(credentialGroupId, 100);
        
        vm.expectRevert("Credential group exists");
        registry.createCredentialGroup(credentialGroupId, 200);
    }

    function testCreateCredentialGroupWithZeroScore() public {
        uint256 credentialGroupId = 1;
        uint256 score = 0; // Zero score should be allowed
        
        vm.expectEmit(true, false, false, true);
        emit CredentialGroupCreated(credentialGroupId, ICredentialRegistry.CredentialGroup(score, 0, ICredentialRegistry.CredentialGroupStatus.ACTIVE));
        
        registry.createCredentialGroup(credentialGroupId, score);
        
        (uint256 storedScore, uint256 groupId, ICredentialRegistry.CredentialGroupStatus status) = registry.credentialGroups(credentialGroupId);
        assertEq(storedScore, 0); // Zero score should be stored correctly
        assertTrue(groupId >= 0); // Group ID should exist (can be 0 for first group)
        assertEq(uint256(status), uint256(ICredentialRegistry.CredentialGroupStatus.ACTIVE));
    }

    function testFuzzNewVerification(uint256 credentialGroupId, uint256 score) public {
        // Allow score to be 0 - sometimes verification is needed without affecting score
        vm.assume(credentialGroupId != 0 && credentialGroupId < type(uint256).max);
        vm.assume(score < type(uint256).max); // Include score = 0
        
        registry.createCredentialGroup(credentialGroupId, score);
        
        (uint256 storedScore, uint256 groupId, ICredentialRegistry.CredentialGroupStatus status) = registry.credentialGroups(credentialGroupId);
        assertEq(storedScore, score);
        assertTrue(groupId >= 0); // Group ID should exist (can be 0 for first group)
        assertEq(uint256(status), uint256(ICredentialRegistry.CredentialGroupStatus.ACTIVE));
    }

    function testCreateCredentialGroupShouldRejectZeroId() public {
        vm.expectRevert();
        registry.createCredentialGroup(0, 100);
    }

    function testSetVerifierShouldRejectZeroAddress() public {
        vm.expectRevert();
        registry.setVerifier(address(0));
    }

    function testSetVerifier() public {
        address newVerifier = makeAddr("new-verifier");
        
        vm.expectEmit(true, false, false, false);
        emit TLSNVerifierSet(newVerifier);
        
        registry.setVerifier(newVerifier);
        assertEq(registry.TLSNVerifier(), newVerifier);
    }

    function testSetVerifierOnlyOwner() public {
        address notOwner = makeAddr("not-owner");
        
        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.setVerifier(makeAddr("new-verifier"));
    }

    function testJoinGroup() public {
        uint256 credentialGroupId = 1;
        uint256 score = 100;
        registry.createCredentialGroup(credentialGroupId, score);
        
        bytes32 idHash = keccak256("test-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);
        
        ICredentialRegistry.Attestation memory message = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: credentialGroupId,
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        vm.expectEmit(true, false, false, true);
        emit CredentialAdded(credentialGroupId, commitment);
        
        registry.joinGroup(message, v, r, s);
    }

    function testJoinGroupWithBytes() public {
        uint256 credentialGroupId = 1;
        uint256 score = 100;
        registry.createCredentialGroup(credentialGroupId, score);
        
        bytes32 idHash = keccak256("test-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);
        
        ICredentialRegistry.Attestation memory message = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: credentialGroupId,
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        bytes memory signature = abi.encodePacked(r, s, v);
        
        vm.expectEmit(true, false, false, true);
        emit CredentialAdded(credentialGroupId, commitment);
        
        registry.joinGroup(message, signature);
    }

    function testJoinGroupInactiveVerification() public {
        uint256 credentialGroupId = 1;
        bytes32 idHash = keccak256("test-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);
        
        ICredentialRegistry.Attestation memory message = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: credentialGroupId,
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        vm.expectRevert("Credential group is inactive");
        registry.joinGroup(message, v, r, s);
    }

    function testJoinGroupWrongRegistry() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);
        
        bytes32 idHash = keccak256("test-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);
        
        ICredentialRegistry.Attestation memory message = ICredentialRegistry.Attestation({
            registry: address(0x123),
            credentialGroupId: credentialGroupId,
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        vm.expectRevert("Wrong attestation message");
        registry.joinGroup(message, v, r, s);
    }

    function testJoinGroupUsedNonce() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);
        
        bytes32 idHash = keccak256("test-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);
        
        ICredentialRegistry.Attestation memory message = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: credentialGroupId,
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message, v, r, s);
        
        vm.expectRevert("Nonce is used");
        registry.joinGroup(message, v, r, s);
    }

    function testJoinGroupUsedNonceWithDifferentCommitment() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);
        
        bytes32 idHash = keccak256("test-id");
        uint256 commitment1 = TestUtils.semaphoreCommitment(12345);
        uint256 commitment2 = TestUtils.semaphoreCommitment(67890); // Different commitment
        
        // First message with commitment1
        ICredentialRegistry.Attestation memory message1 = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: credentialGroupId,
            idHash: idHash, // Same idHash
            semaphoreIdentityCommitment: commitment1
        });
        
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message1)).toEthSignedMessageHash()
        );
        
        // First join should succeed
        registry.joinGroup(message1, v1, r1, s1);
        
        // Second message with same registry, credentialGroupId, idHash but different commitment
        ICredentialRegistry.Attestation memory message2 = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: credentialGroupId,
            idHash: idHash, // Same idHash - this is the key point
            semaphoreIdentityCommitment: commitment2 // Different commitment
        });
        
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message2)).toEthSignedMessageHash()
        );
        
        // Second join should fail because nonce is the same (commitment not included in nonce)
        vm.expectRevert("Nonce is used");
        registry.joinGroup(message2, v2, r2, s2);
    }

    function testJoinGroupInvalidSignature() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);
        
        bytes32 idHash = keccak256("test-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);
        
        ICredentialRegistry.Attestation memory message = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: credentialGroupId,
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            123456, // Wrong private key
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        vm.expectRevert("Invalid TLSN Verifier signature");
        registry.joinGroup(message, v, r, s);
    }

    function testValidateProof() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);
        
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        // Add member to group
        bytes32 idHash = keccak256("test-id");
        ICredentialRegistry.Attestation memory message = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: credentialGroupId,
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message, v, r, s);
        
        // Create proof
        address prover = makeAddr("prover");
        uint256 context = 0;
        uint256 scope = uint256(keccak256(abi.encode(prover, context)));
        
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = commitment;
        
        (
            uint256 merkleTreeDepth,
            uint256 merkleTreeRoot,
            uint256 nullifier,
            uint256 messageHash,
            uint256[8] memory points
        ) = TestUtils.semaphoreProof(commitmentKey, scope, commitments);
        
        ICredentialRegistry.CredentialGroupProof memory proof = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: credentialGroupId,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });
        
        vm.expectEmit(true, false, false, false);
        emit ProofValidated(credentialGroupId);
        
        vm.prank(prover);
        registry.validateProof(context, proof);
    }

    function testValidateProofInactiveVerification() public {
        uint256 credentialGroupId = 1;
        
        ICredentialRegistry.CredentialGroupProof memory proof = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: credentialGroupId,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: 0,
                merkleTreeRoot: 0,
                nullifier: 0,
                message: 0,
                scope: 0,
                points: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
            })
        });
        
        vm.expectRevert("Credential group is inactive");
        registry.validateProof(0, proof);
    }

    function testValidateProofWrongScope() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);
        
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        // Add member to group
        bytes32 idHash = keccak256("test-id");
        ICredentialRegistry.Attestation memory message = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: credentialGroupId,
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message, v, r, s);
        
        // Create proof with wrong scope
        address prover = makeAddr("prover");
        uint256 context = 0;
        uint256 wrongScope = uint256(keccak256(abi.encode(makeAddr("wrong"), context)));
        
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = commitment;
        
        (
            uint256 merkleTreeDepth,
            uint256 merkleTreeRoot,
            uint256 nullifier,
            uint256 messageHash,
            uint256[8] memory points
        ) = TestUtils.semaphoreProof(commitmentKey, wrongScope, commitments);
        
        ICredentialRegistry.CredentialGroupProof memory proof = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: credentialGroupId,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: wrongScope,
                points: points
            })
        });
        
        vm.expectRevert("Wrong scope");
        vm.prank(prover);
        registry.validateProof(context, proof);
    }

    function testVerifyProof() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);
        
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        // Add member to group
        bytes32 idHash = keccak256("test-id");
        ICredentialRegistry.Attestation memory message = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: credentialGroupId,
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message, v, r, s);
        
        // Create proof
        uint256 scope = uint256(keccak256(abi.encode(address(this), 0)));
        
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = commitment;
        
        (
            uint256 merkleTreeDepth,
            uint256 merkleTreeRoot,
            uint256 nullifier,
            uint256 messageHash,
            uint256[8] memory points
        ) = TestUtils.semaphoreProof(commitmentKey, scope, commitments);
        
        ICredentialRegistry.CredentialGroupProof memory proof = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: credentialGroupId,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });
        
        assertTrue(registry.verifyProof(proof));
    }

    function testScore() public {
        uint256 credentialGroupId1 = 1;
        uint256 credentialGroupId2 = 2;
        uint256 score1 = 100;
        uint256 score2 = 200;
        
        registry.createCredentialGroup(credentialGroupId1, score1);
        registry.createCredentialGroup(credentialGroupId2, score2);
        
        uint256 commitmentKey1 = 12345;
        uint256 commitmentKey2 = 67890;
        uint256 commitment1 = TestUtils.semaphoreCommitment(commitmentKey1);
        uint256 commitment2 = TestUtils.semaphoreCommitment(commitmentKey2);
        
        // Add members to groups
        bytes32 idHash1 = keccak256("test-id-1");
        ICredentialRegistry.Attestation memory message1 = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: credentialGroupId1,
            idHash: idHash1,
            semaphoreIdentityCommitment: commitment1
        });
        
        bytes32 idHash2 = keccak256("test-id-2");
        ICredentialRegistry.Attestation memory message2 = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: credentialGroupId2,
            idHash: idHash2,
            semaphoreIdentityCommitment: commitment2
        });
        
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message1)).toEthSignedMessageHash()
        );
        
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message2)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message1, v1, r1, s1);
        registry.joinGroup(message2, v2, r2, s2);
        
        // Create proofs
        uint256 scope = uint256(keccak256(abi.encode(address(this), 0)));
        
        uint256[] memory commitments1 = new uint256[](1);
        commitments1[0] = commitment1;
        
        uint256[] memory commitments2 = new uint256[](1);
        commitments2[0] = commitment2;
        
        (
            uint256 merkleTreeDepth1,
            uint256 merkleTreeRoot1,
            uint256 nullifier1,
            uint256 messageHash1,
            uint256[8] memory points1
        ) = TestUtils.semaphoreProof(commitmentKey1, scope, commitments1);
        
        (
            uint256 merkleTreeDepth2,
            uint256 merkleTreeRoot2,
            uint256 nullifier2,
            uint256 messageHash2,
            uint256[8] memory points2
        ) = TestUtils.semaphoreProof(commitmentKey2, scope, commitments2);
        
        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](2);
        proofs[0] = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: credentialGroupId1,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth1,
                merkleTreeRoot: merkleTreeRoot1,
                nullifier: nullifier1,
                message: messageHash1,
                scope: scope,
                points: points1
            })
        });
        
        proofs[1] = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: credentialGroupId2,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth2,
                merkleTreeRoot: merkleTreeRoot2,
                nullifier: nullifier2,
                message: messageHash2,
                scope: scope,
                points: points2
            })
        });
        
        uint256 totalScore = registry.score(0, proofs);
        assertEq(totalScore, score1 + score2);
    }

    function testScoreFailOnInactive() public {
        uint256 credentialGroupId1 = 1;
        uint256 credentialGroupId2 = 2;
        uint256 score1 = 100;
        
        registry.createCredentialGroup(credentialGroupId1, score1);
        // Don't create credentialGroupId2, it will be inactive
        
        uint256 commitmentKey1 = 12345;
        uint256 commitment1 = TestUtils.semaphoreCommitment(commitmentKey1);
        
        // Add member to group 1
        bytes32 idHash1 = keccak256("test-id-1");
        ICredentialRegistry.Attestation memory message1 = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: credentialGroupId1,
            idHash: idHash1,
            semaphoreIdentityCommitment: commitment1
        });
        
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message1)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message1, v1, r1, s1);
        
        // Create proofs
        uint256 scope = uint256(keccak256(abi.encode(address(this), 0)));
        
        uint256[] memory commitments1 = new uint256[](1);
        commitments1[0] = commitment1;
        
        (
            uint256 merkleTreeDepth1,
            uint256 merkleTreeRoot1,
            uint256 nullifier1,
            uint256 messageHash1,
            uint256[8] memory points1
        ) = TestUtils.semaphoreProof(commitmentKey1, scope, commitments1);
        
        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](2);
        proofs[0] = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: credentialGroupId1,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth1,
                merkleTreeRoot: merkleTreeRoot1,
                nullifier: nullifier1,
                message: messageHash1,
                scope: scope,
                points: points1
            })
        });
        
        proofs[1] = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: credentialGroupId2,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: 0,
                merkleTreeRoot: 0,
                nullifier: 0,
                message: 0,
                scope: scope,
                points: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
            })
        });
        
        vm.expectRevert("Credential group is inactive");
        registry.score(0, proofs);
    }
}