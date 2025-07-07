// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import {BringDropByVerification} from "../src/drop/BringDropByVerification.sol";
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

contract BringDropByVerificationTest is Test {
    using ECDSA for bytes32;

    BringDropByVerification drop;
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
    
    uint256 constant VERIFICATION_ID = 1;
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

        // Create verification in registry
        registry.newVerification(VERIFICATION_ID, 100);

        // Deploy drop
        drop = new BringDropByVerification(
            VERIFICATION_ID,
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
        assertEq(drop.verificationId(), VERIFICATION_ID);
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

    function testClaim() public {
        // Setup user with commitment
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        // Add member to group
        bytes32 idHash = keccak256("test-id");
        IBringRegistry.TLSNVerifierMessage memory message = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID,
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
        
        IBringRegistry.VerificationProof memory proof = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });
        
        uint256 initialBalance = token.balanceOf(recipient);
        uint256 initialClaims = drop.claims();
        
        drop.claim(proof, recipient);
        
        assertEq(token.balanceOf(recipient), initialBalance + AMOUNT);
        assertEq(drop.claims(), initialClaims + 1);
    }

    function testClaimWrongVerification() public {
        // Setup user with commitment
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        // Add member to group
        bytes32 idHash = keccak256("test-id");
        IBringRegistry.TLSNVerifierMessage memory message = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID,
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message, v, r, s);
        
        // Create proof with wrong verification ID
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
        
        IBringRegistry.VerificationProof memory proof = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID + 1, // Wrong verification ID
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });
        
        vm.expectRevert("Wrong Verification");
        drop.claim(proof, recipient);
    }

    function testClaimExhausted() public {
        // Create a drop with max claims = 1
        BringDropByVerification smallDrop = new BringDropByVerification(
            VERIFICATION_ID,
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
            verificationId: VERIFICATION_ID,
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
        
        IBringRegistry.VerificationProof memory proof = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });
        
        // First claim should succeed
        smallDrop.claim(proof, recipient);
        assertEq(smallDrop.claims(), 1);
        
        // Second claim should fail
        vm.expectRevert("All claims exhausted");
        smallDrop.claim(proof, recipient);
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
        
        IBringRegistry.VerificationProof memory proof = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID,
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
        drop.claim(proof, recipient);
    }

    function testClaimTokenTransferFails() public {
        // Create drop with no token balance
        BringDropByVerification emptyDrop = new BringDropByVerification(
            VERIFICATION_ID,
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
            verificationId: VERIFICATION_ID,
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
        
        IBringRegistry.VerificationProof memory proof = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID,
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
        emptyDrop.claim(proof, recipient);
    }

    function testMultipleClaims() public {
        // Setup first user
        uint256 commitmentKey1 = 12345;
        uint256 commitment1 = TestUtils.semaphoreCommitment(commitmentKey1);
        
        bytes32 idHash1 = keccak256("test-id-1");
        IBringRegistry.TLSNVerifierMessage memory message1 = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID,
            idHash: idHash1,
            semaphoreIdentityCommitment: commitment1
        });
        
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message1)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message1, v1, r1, s1);
        
        // Setup second user
        uint256 commitmentKey2 = 67890;
        uint256 commitment2 = TestUtils.semaphoreCommitment(commitmentKey2);
        
        bytes32 idHash2 = keccak256("test-id-2");
        IBringRegistry.TLSNVerifierMessage memory message2 = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID,
            idHash: idHash2,
            semaphoreIdentityCommitment: commitment2
        });
        
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message2)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message2, v2, r2, s2);
        
        // Create proofs
        uint256 scope = uint256(keccak256(abi.encode(address(drop), 0)));
        
        uint256[] memory commitments1 = new uint256[](2);
        commitments1[0] = commitment1;
        commitments1[1] = commitment2;
        
        uint256[] memory commitments2 = new uint256[](2);
        commitments2[0] = commitment1;
        commitments2[1] = commitment2;
        
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
        
        IBringRegistry.VerificationProof memory proof1 = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth1,
                merkleTreeRoot: merkleTreeRoot1,
                nullifier: nullifier1,
                message: messageHash1,
                scope: scope,
                points: points1
            })
        });
        
        IBringRegistry.VerificationProof memory proof2 = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID,
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
        
        // First claim
        drop.claim(proof1, recipient1);
        assertEq(token.balanceOf(recipient1), AMOUNT);
        assertEq(drop.claims(), 1);
        
        // Second claim
        drop.claim(proof2, recipient2);
        assertEq(token.balanceOf(recipient2), AMOUNT);
        assertEq(drop.claims(), 2);
    }

    function testFuzzClaim(uint256 commitmentKey, address to) public {
        vm.assume(commitmentKey > 0);
        vm.assume(to != address(0));
        
        // Setup user with commitment
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        // Add member to group
        bytes32 idHash = keccak256(abi.encode(commitmentKey));
        IBringRegistry.TLSNVerifierMessage memory message = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID,
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
        
        IBringRegistry.VerificationProof memory proof = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });
        
        uint256 initialBalance = token.balanceOf(to);
        uint256 initialClaims = drop.claims();
        
        drop.claim(proof, to);
        
        assertEq(token.balanceOf(to), initialBalance + AMOUNT);
        assertEq(drop.claims(), initialClaims + 1);
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
            verificationId: VERIFICATION_ID,
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
        
        IBringRegistry.VerificationProof memory proof = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID,
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
        drop.claim(proof, recipient);
    }

    function testSameUserCannotClaimTwice() public {
        // Setup user with commitment
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        // Add member to group
        bytes32 idHash = keccak256("test-id");
        IBringRegistry.TLSNVerifierMessage memory message = IBringRegistry.TLSNVerifierMessage({
            registry: address(registry),
            verificationId: VERIFICATION_ID,
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
        
        IBringRegistry.VerificationProof memory proof = IBringRegistry.VerificationProof({
            verificationId: VERIFICATION_ID,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });
        
        // First claim should succeed
        drop.claim(proof, recipient);
        assertEq(token.balanceOf(recipient), AMOUNT);
        assertEq(drop.claims(), 1);
        
        // Second claim with same proof should fail (nullifier already used)
        vm.expectRevert();
        drop.claim(proof, recipient);
    }
}