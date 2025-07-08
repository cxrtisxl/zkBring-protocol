// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import {BringDropByScore} from "../src/drop/BringDropByScore.sol";
import {BringRegistry} from "../src/registry/BringRegistry.sol";
import {IBringRegistry} from "../src/registry/IBringRegistry.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {ISemaphoreVerifier} from "semaphore-protocol/interfaces/ISemaphoreVerifier.sol";
import {SemaphoreVerifier} from "semaphore-protocol/base/SemaphoreVerifier.sol";
import {Semaphore} from "semaphore-protocol/Semaphore.sol";
import {Token} from "../src/mock/Token.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {TestUtils} from "./TestUtils.sol";

contract BringDropByScoreTest is Test {
    using ECDSA for bytes32;

    BringDropByScore drop;
    BringRegistry registry;
    Semaphore semaphore;
    SemaphoreVerifier semaphoreVerifier;
    Token token;
    Token bringToken;
    
    address creator;
    address user;
    address recipient;
    address tlsnVerifier;
    uint256 tlsnVerifierPrivateKey;
    
    uint256 constant VERIFICATION_ID_1 = 1;
    uint256 constant VERIFICATION_ID_2 = 2;
    uint256 constant VERIFICATION_ID_3 = 3;
    uint256 constant SCORE_THRESHOLD = 200;
    uint256 constant AMOUNT = 10 * 10**18;
    uint256 constant MAX_CLAIMS = 100;
    uint256 constant TOKEN_SUPPLY = 1000000 * 10**18;
    uint256 expiration;
    string constant METADATA_HASH = "QmTestHash";

    function setUp() public {
        creator = makeAddr("creator");
        user = makeAddr("user");
        recipient = makeAddr("recipient");
        (tlsnVerifier, tlsnVerifierPrivateKey) = makeAddrAndKey("tlsn-verifier");
        expiration = block.timestamp + 7 days;
        
        // Deploy tokens
        token = new Token("Test Token", "TEST", user, TOKEN_SUPPLY);
        bringToken = new Token("Bring Token", "BRING", user, TOKEN_SUPPLY);
        
        // Deploy Semaphore contracts
        semaphoreVerifier = new SemaphoreVerifier();
        semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));
        
        // Deploy registry
        registry = new BringRegistry(ISemaphore(address(semaphore)), tlsnVerifier);

        // Create verifications in registry
        registry.newVerification(VERIFICATION_ID_1, 100);
        registry.newVerification(VERIFICATION_ID_2, 150);
        registry.newVerification(VERIFICATION_ID_3, 50);

        // Deploy drop
        drop = new BringDropByScore(
            SCORE_THRESHOLD,
            IBringRegistry(address(registry)),
            creator,
            IERC20(address(token)),
            AMOUNT,
            MAX_CLAIMS,
            expiration,
            METADATA_HASH,
            IERC20(address(bringToken))
        );
        
        // Fund the drop with tokens
        vm.prank(user);
        token.transfer(address(drop), AMOUNT * MAX_CLAIMS);
    }

    function testConstructor() public {
        assertEq(drop.scoreThreshold(), SCORE_THRESHOLD);
        assertEq(address(drop.registry()), address(registry));
        assertEq(address(drop.token()), address(token));
        assertEq(drop.amount(), AMOUNT);
        assertEq(drop.maxClaims(), MAX_CLAIMS);
        assertEq(drop.expiration(), expiration);
        assertEq(drop.metadataIpfsHash(), METADATA_HASH);
        assertEq(address(drop.BRING_TOKEN()), address(bringToken));
        assertEq(drop.owner(), creator);
        assertEq(drop.claims(), 0);
        assertFalse(drop.stopped());
    }

    function testClaimWithSufficientScore() public {
        // Setup user with commitments for multiple verifications
        uint256 commitmentKey1 = 12345;
        uint256 commitmentKey2 = 67890;
        uint256 commitmentKey3 = 11111;
        
        uint256 commitment1 = TestUtils.semaphoreCommitment(commitmentKey1);
        uint256 commitment2 = TestUtils.semaphoreCommitment(commitmentKey2);
        uint256 commitment3 = TestUtils.semaphoreCommitment(commitmentKey3);
        
        // Add members to groups
        bytes32 idHash1 = keccak256("test-id-1");
        bytes32 idHash2 = keccak256("test-id-2");
        bytes32 idHash3 = keccak256("test-id-3");
        
        IBringRegistry.TLSNVerifierMessage memory message1 = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID_1,
            idHash: idHash1,
            semaphoreIdentityCommitment: commitment1
        });
        
        IBringRegistry.TLSNVerifierMessage memory message2 = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID_2,
            idHash: idHash2,
            semaphoreIdentityCommitment: commitment2
        });
        
        IBringRegistry.TLSNVerifierMessage memory message3 = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID_3,
            idHash: idHash3,
            semaphoreIdentityCommitment: commitment3
        });
        
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message1)).toEthSignedMessageHash()
        );
        
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message2)).toEthSignedMessageHash()
        );
        
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message3)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message1, v1, r1, s1);
        registry.joinGroup(message2, v2, r2, s2);
        registry.joinGroup(message3, v3, r3, s3);
        
        // Create proofs
        uint256 scope = uint256(keccak256(abi.encode(address(drop), 0)));
        
        // For separate groups, each commitment should be in its own array
        uint256[] memory commitments1 = new uint256[](1);
        commitments1[0] = commitment1;
        
        uint256[] memory commitments2 = new uint256[](1);
        commitments2[0] = commitment2;
        
        uint256[] memory commitments3 = new uint256[](1);
        commitments3[0] = commitment3;
        
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
        
        (
            uint256 merkleTreeDepth3,
            uint256 merkleTreeRoot3,
            uint256 nullifier3,
            uint256 messageHash3,
            uint256[8] memory points3
        ) = TestUtils.semaphoreProof(commitmentKey3, scope, commitments3);
        
        IBringRegistry.VerificationProof[] memory proofs = new IBringRegistry.VerificationProof[](3);
        proofs[0] = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID_1,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth1,
                merkleTreeRoot: merkleTreeRoot1,
                nullifier: nullifier1,
                message: messageHash1,
                scope: scope,
                points: points1
            })
        });
        
        proofs[1] = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID_2,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth2,
                merkleTreeRoot: merkleTreeRoot2,
                nullifier: nullifier2,
                message: messageHash2,
                scope: scope,
                points: points2
            })
        });
        
        proofs[2] = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID_3,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth3,
                merkleTreeRoot: merkleTreeRoot3,
                nullifier: nullifier3,
                message: messageHash3,
                scope: scope,
                points: points3
            })
        });
        
        uint256 initialBalance = token.balanceOf(recipient);
        uint256 initialClaims = drop.claims();
        
        // Total score: 100 + 150 + 50 = 300 > 200 threshold
        vm.prank(recipient);
        drop.claim(proofs);
        
        assertEq(token.balanceOf(recipient), initialBalance + AMOUNT);
        assertEq(drop.claims(), initialClaims + 1);
    }

    function testClaimWithInsufficientScore() public {
        // Setup user with commitment for only one verification
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        // Add member to group
        bytes32 idHash = keccak256("test-id");
        IBringRegistry.TLSNVerifierMessage memory message = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID_3, // Score = 50
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message, v, r, s);
        
        // Create proof
        uint256 scope = uint256(keccak256(abi.encode(address(drop), 0)));
        
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = commitment;
        
        (
            uint256 merkleTreeDepth,
            uint256 merkleTreeRoot,
            uint256 nullifier,
            uint256 messageHash,
            uint256[8] memory points
        ) = TestUtils.semaphoreProof(commitmentKey, scope, commitments);
        
        IBringRegistry.VerificationProof[] memory proofs = new IBringRegistry.VerificationProof[](1);
        proofs[0] = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID_3,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });
        
        // Score = 50 < 200 threshold (need > 200)
        vm.expectRevert("Insufficient score");
        drop.claim(proofs);
    }

    function testClaimWithZeroScoreVerification() public {
        // Create verification with score 0
        uint256 zeroScoreVerificationId = 99;
        registry.newVerification(zeroScoreVerificationId, 0);
        
        // Setup user with commitment
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        // Add member to group
        bytes32 idHash = keccak256("test-id");
        IBringRegistry.TLSNVerifierMessage memory message = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: zeroScoreVerificationId,
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message, v, r, s);
        
        // Create proof
        uint256 scope = uint256(keccak256(abi.encode(address(drop), 0)));
        
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = commitment;
        
        (
            uint256 merkleTreeDepth,
            uint256 merkleTreeRoot,
            uint256 nullifier,
            uint256 messageHash,
            uint256[8] memory points
        ) = TestUtils.semaphoreProof(commitmentKey, scope, commitments);
        
        IBringRegistry.VerificationProof[] memory proofs = new IBringRegistry.VerificationProof[](1);
        proofs[0] = IBringRegistry.VerificationProof({
            verificationId: zeroScoreVerificationId,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });
        
        // Score = 0 < 200 threshold (need > 200)
        vm.expectRevert("Insufficient score");
        drop.claim(proofs);
    }

    function testClaimExhausted() public {
        // Create a drop with max claims = 1
        BringDropByScore smallDrop = new BringDropByScore(
            50, // Low threshold
            IBringRegistry(address(registry)),
            creator,
            IERC20(address(token)),
            AMOUNT,
            1, // Max claims = 1
            expiration,
            METADATA_HASH,
            IERC20(address(bringToken))
        );
        
        // Fund the drop
        vm.prank(user);
        token.transfer(address(smallDrop), AMOUNT);
        
        // Setup user with commitment
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        // Add member to group
        bytes32 idHash = keccak256("test-id");
        IBringRegistry.TLSNVerifierMessage memory message = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID_1,
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message, v, r, s);
        
        // Create proof
        uint256 scope = uint256(keccak256(abi.encode(address(smallDrop), 0)));
        
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = commitment;
        
        (
            uint256 merkleTreeDepth,
            uint256 merkleTreeRoot,
            uint256 nullifier,
            uint256 messageHash,
            uint256[8] memory points
        ) = TestUtils.semaphoreProof(commitmentKey, scope, commitments);
        
        IBringRegistry.VerificationProof[] memory proofs = new IBringRegistry.VerificationProof[](1);
        proofs[0] = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID_1,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });
        
        // First claim should succeed (score = 100 > 50 threshold)
        smallDrop.claim(proofs);
        assertEq(smallDrop.claims(), 1);
        
        // Second claim should fail
        vm.expectRevert("All claims exhausted");
        smallDrop.claim(proofs);
    }

    function testClaimInvalidProof() public {
        // Create proof without adding member to group
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        uint256 scope = uint256(keccak256(abi.encode(address(drop), 0)));
        
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = commitment;
        
        (
            uint256 merkleTreeDepth,
            uint256 merkleTreeRoot,
            uint256 nullifier,
            uint256 messageHash,
            uint256[8] memory points
        ) = TestUtils.semaphoreProof(commitmentKey, scope, commitments);
        
        IBringRegistry.VerificationProof[] memory proofs = new IBringRegistry.VerificationProof[](1);
        proofs[0] = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID_1,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });
        
        // This should fail because the proof is invalid (member not in group)
        vm.expectRevert();
        drop.claim(proofs);
    }

    function testClaimTokenTransferFails() public {
        // Create drop with no token balance
        BringDropByScore emptyDrop = new BringDropByScore(
            50, // Low threshold
            IBringRegistry(address(registry)),
            creator,
            IERC20(address(token)),
            AMOUNT,
            MAX_CLAIMS,
            expiration,
            METADATA_HASH,
            IERC20(address(bringToken))
        );
        
        // Setup user with commitment
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        // Add member to group
        bytes32 idHash = keccak256("test-id");
        IBringRegistry.TLSNVerifierMessage memory message = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID_1,
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message, v, r, s);
        
        // Create proof
        uint256 scope = uint256(keccak256(abi.encode(address(emptyDrop), 0)));
        
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = commitment;
        
        (
            uint256 merkleTreeDepth,
            uint256 merkleTreeRoot,
            uint256 nullifier,
            uint256 messageHash,
            uint256[8] memory points
        ) = TestUtils.semaphoreProof(commitmentKey, scope, commitments);
        
        IBringRegistry.VerificationProof[] memory proofs = new IBringRegistry.VerificationProof[](1);
        proofs[0] = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID_1,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });
        
        vm.expectRevert("ERC20: transfer amount exceeds balance");
        emptyDrop.claim(proofs);
    }

    function testCannotReuseNullifiers() public {
        // Setup two different users
        uint256 commitmentKey1 = 12345;
        uint256 commitmentKey2 = 67890;
        
        uint256 commitment1 = TestUtils.semaphoreCommitment(commitmentKey1);
        uint256 commitment2 = TestUtils.semaphoreCommitment(commitmentKey2);
        
        // Add members to groups
        bytes32 idHash1 = keccak256("test-id-1");
        bytes32 idHash2 = keccak256("test-id-2");
        
        IBringRegistry.TLSNVerifierMessage memory message1 = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID_1,
            idHash: idHash1,
            semaphoreIdentityCommitment: commitment1
        });
        
        IBringRegistry.TLSNVerifierMessage memory message2 = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID_2,
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
        uint256 scope = uint256(keccak256(abi.encode(address(drop), 0)));
        
        // For separate groups, each commitment should be in its own array
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
        
        IBringRegistry.VerificationProof[] memory proofs1 = new IBringRegistry.VerificationProof[](2);
        proofs1[0] = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID_1,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth1,
                merkleTreeRoot: merkleTreeRoot1,
                nullifier: nullifier1,
                message: messageHash1,
                scope: scope,
                points: points1
            })
        });
        
        proofs1[1] = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID_2,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth2,
                merkleTreeRoot: merkleTreeRoot2,
                nullifier: nullifier2,
                message: messageHash2,
                scope: scope,
                points: points2
            })
        });
        
        IBringRegistry.VerificationProof[] memory proofs2 = new IBringRegistry.VerificationProof[](2);
        proofs2[0] = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID_1,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth1,
                merkleTreeRoot: merkleTreeRoot1,
                nullifier: nullifier1,
                message: messageHash1,
                scope: scope,
                points: points1
            })
        });
        
        proofs2[1] = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID_2,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth2,
                merkleTreeRoot: merkleTreeRoot2,
                nullifier: nullifier2,
                message: messageHash2,
                scope: scope,
                points: points2
            })
        });
        
        address recipient1 = makeAddr("recipient1");
        address recipient2 = makeAddr("recipient2");
        
        // First claim (score = 100 + 150 = 250 > 200 threshold)
        vm.prank(recipient1);
        drop.claim(proofs1);
        assertEq(token.balanceOf(recipient1), AMOUNT);
        assertEq(drop.claims(), 1);
        
        // Second claim should fail because nullifiers are already used
        vm.expectRevert();
        vm.prank(recipient2);
        drop.claim(proofs2);
    }

    function testClaimAfterStop() public {
        // Stop the drop
        vm.prank(creator);
        drop.stop();
        
        // Setup user with commitment
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        // Add member to group
        bytes32 idHash = keccak256("test-id");
        IBringRegistry.TLSNVerifierMessage memory message = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID_1,
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message, v, r, s);
        
        // Create proof
        uint256 scope = uint256(keccak256(abi.encode(address(drop), 0)));
        
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = commitment;
        
        (
            uint256 merkleTreeDepth,
            uint256 merkleTreeRoot,
            uint256 nullifier,
            uint256 messageHash,
            uint256[8] memory points
        ) = TestUtils.semaphoreProof(commitmentKey, scope, commitments);
        
        IBringRegistry.VerificationProof[] memory proofs = new IBringRegistry.VerificationProof[](1);
        proofs[0] = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID_1,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });
        
        // Claim should fail because drop is stopped
        vm.expectRevert("Campaign stopped");
        drop.claim(proofs);
    }

    function testClaimAfterExpiration() public {
        // Fast forward past expiration
        vm.warp(expiration + 1);
        
        // Setup user with commitment
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        // Add member to group
        bytes32 idHash = keccak256("test-id");
        IBringRegistry.TLSNVerifierMessage memory message = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID_1,
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message, v, r, s);
        
        // Create proof
        uint256 scope = uint256(keccak256(abi.encode(address(drop), 0)));
        
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = commitment;
        
        (
            uint256 merkleTreeDepth,
            uint256 merkleTreeRoot,
            uint256 nullifier,
            uint256 messageHash,
            uint256[8] memory points
        ) = TestUtils.semaphoreProof(commitmentKey, scope, commitments);
        
        IBringRegistry.VerificationProof[] memory proofs = new IBringRegistry.VerificationProof[](1);
        proofs[0] = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID_1,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });
        
        // Claim should fail because drop is expired
        vm.expectRevert("Drop has expired");
        drop.claim(proofs);
    }

    function testSameUserCannotClaimTwice() public {
        // Setup user with commitments for multiple verifications to reach threshold
        uint256 commitmentKey1 = 12345;
        uint256 commitmentKey2 = 67890;
        uint256 commitmentKey3 = 11111;
        
        uint256 commitment1 = TestUtils.semaphoreCommitment(commitmentKey1);
        uint256 commitment2 = TestUtils.semaphoreCommitment(commitmentKey2);
        uint256 commitment3 = TestUtils.semaphoreCommitment(commitmentKey3);
        
        // Add members to groups
        bytes32 idHash1 = keccak256("test-id-1");
        bytes32 idHash2 = keccak256("test-id-2");
        bytes32 idHash3 = keccak256("test-id-3");
        
        IBringRegistry.TLSNVerifierMessage memory message1 = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID_1,
            idHash: idHash1,
            semaphoreIdentityCommitment: commitment1
        });
        
        IBringRegistry.TLSNVerifierMessage memory message2 = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID_2,
            idHash: idHash2,
            semaphoreIdentityCommitment: commitment2
        });
        
        IBringRegistry.TLSNVerifierMessage memory message3 = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID_3,
            idHash: idHash3,
            semaphoreIdentityCommitment: commitment3
        });
        
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message1)).toEthSignedMessageHash()
        );
        
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message2)).toEthSignedMessageHash()
        );
        
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message3)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message1, v1, r1, s1);
        registry.joinGroup(message2, v2, r2, s2);
        registry.joinGroup(message3, v3, r3, s3);
        
        // Create proofs
        uint256 scope = uint256(keccak256(abi.encode(address(drop), 0)));
        
        uint256[] memory commitments1 = new uint256[](1);
        commitments1[0] = commitment1;
        
        uint256[] memory commitments2 = new uint256[](1);
        commitments2[0] = commitment2;
        
        uint256[] memory commitments3 = new uint256[](1);
        commitments3[0] = commitment3;
        
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
        
        (
            uint256 merkleTreeDepth3,
            uint256 merkleTreeRoot3,
            uint256 nullifier3,
            uint256 messageHash3,
            uint256[8] memory points3
        ) = TestUtils.semaphoreProof(commitmentKey3, scope, commitments3);
        
        IBringRegistry.VerificationProof[] memory proofs = new IBringRegistry.VerificationProof[](3);
        proofs[0] = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID_1,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth1,
                merkleTreeRoot: merkleTreeRoot1,
                nullifier: nullifier1,
                message: messageHash1,
                scope: scope,
                points: points1
            })
        });
        
        proofs[1] = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID_2,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth2,
                merkleTreeRoot: merkleTreeRoot2,
                nullifier: nullifier2,
                message: messageHash2,
                scope: scope,
                points: points2
            })
        });
        
        proofs[2] = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID_3,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth3,
                merkleTreeRoot: merkleTreeRoot3,
                nullifier: nullifier3,
                message: messageHash3,
                scope: scope,
                points: points3
            })
        });
        
        // First claim should succeed (score = 100 + 150 + 50 = 300 > 200 threshold)
        vm.prank(recipient);
        drop.claim(proofs);
        assertEq(token.balanceOf(recipient), AMOUNT);
        assertEq(drop.claims(), 1);
        
        // Second claim with same proof should fail (nullifier already used)
        vm.expectRevert();
        vm.prank(recipient);
        drop.claim(proofs);
    }

    function testClaimWithInactiveVerification() public {
        // Setup user with commitment
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        // Create proof for non-existent verification
        uint256 scope = uint256(keccak256(abi.encode(address(drop), 0)));
        
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = commitment;
        
        (
            uint256 merkleTreeDepth,
            uint256 merkleTreeRoot,
            uint256 nullifier,
            uint256 messageHash,
            uint256[8] memory points
        ) = TestUtils.semaphoreProof(commitmentKey, scope, commitments);
        
        IBringRegistry.VerificationProof[] memory proofs = new IBringRegistry.VerificationProof[](1);
        proofs[0] = IBringRegistry.VerificationProof({
            verificationId: 999, // Non-existent verification
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });
        
        // Should fail because verification is inactive (skipped by score() with skipInactive=true, results in 0 score)
        vm.expectRevert("Insufficient score");
        drop.claim(proofs);
    }

    function testInheritedFunctionality() public {
        // Test that inherited functions from BringDropBase work correctly
        
        // Test staking
        uint256 stakeAmount = 100 * 10**18;
        
        // Transfer tokens to creator first
        vm.prank(user);
        bringToken.transfer(creator, stakeAmount);
        
        vm.startPrank(creator);
        bringToken.approve(address(drop), stakeAmount);
        drop.stake(stakeAmount);
        assertEq(drop.bringStaked(), stakeAmount);
        
        // Test metadata update
        string memory newMetadata = "QmNewTestHash";
        drop.updateMetadata(newMetadata);
        assertEq(drop.metadataIpfsHash(), newMetadata);
        
        // Test stop
        uint256 initialTokenBalance = token.balanceOf(address(drop));
        drop.stop();
        assertTrue(drop.stopped());
        assertEq(token.balanceOf(creator), initialTokenBalance);
        assertEq(bringToken.balanceOf(creator), stakeAmount);
        
        vm.stopPrank();
    }

    function testFuzzClaim(uint256 scoreThreshold, uint256 commitmentKey) public {
        scoreThreshold = bound(scoreThreshold, 1, 300);
        commitmentKey = bound(commitmentKey, 1, type(uint256).max);
        
        // Create a drop with fuzzed score threshold
        BringDropByScore fuzzDrop = new BringDropByScore(
            scoreThreshold,
            IBringRegistry(address(registry)),
            creator,
            IERC20(address(token)),
            AMOUNT,
            MAX_CLAIMS,
            expiration,
            METADATA_HASH,
            IERC20(address(bringToken))
        );
        
        // Fund the drop
        vm.prank(user);
        token.transfer(address(fuzzDrop), AMOUNT);
        
        // Setup user with commitment
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        // Add member to group (using highest score verification)
        bytes32 idHash = keccak256(abi.encode(commitmentKey));
        IBringRegistry.TLSNVerifierMessage memory message = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID_2, // Score = 150
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message, v, r, s);
        
        // Create proof
        uint256 scope = uint256(keccak256(abi.encode(address(fuzzDrop), 0)));
        
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = commitment;
        
        (
            uint256 merkleTreeDepth,
            uint256 merkleTreeRoot,
            uint256 nullifier,
            uint256 messageHash,
            uint256[8] memory points
        ) = TestUtils.semaphoreProof(commitmentKey, scope, commitments);
        
        IBringRegistry.VerificationProof[] memory proofs = new IBringRegistry.VerificationProof[](1);
        proofs[0] = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID_2,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });
        
        if (150 > scoreThreshold) {
            // Should succeed
            uint256 initialBalance = token.balanceOf(recipient);
            vm.prank(recipient);
            fuzzDrop.claim(proofs);
            assertEq(token.balanceOf(recipient), initialBalance + AMOUNT);
            assertEq(fuzzDrop.claims(), 1);
        } else {
            // Should fail with insufficient score
            vm.expectRevert("Insufficient score");
            vm.prank(recipient);
            fuzzDrop.claim(proofs);
        }
    }
}