// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import {IdCard} from "../src/id_card/IdCard.sol";
import {ICredentialRegistry} from "../src/registry/ICredentialRegistry.sol";
import {CredentialRegistry} from "../src/registry/CredentialRegistry.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {ISemaphoreVerifier} from "semaphore-protocol/interfaces/ISemaphoreVerifier.sol";
import {SemaphoreVerifier} from "semaphore-protocol/base/SemaphoreVerifier.sol";
import {Semaphore} from "semaphore-protocol/Semaphore.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {TestUtils} from "./TestUtils.sol";

contract IdCardTest is Test {
    using ECDSA for bytes32;

    IdCard idCard;
    CredentialRegistry registry;
    Semaphore semaphore;
    SemaphoreVerifier semaphoreVerifier;
    
    address owner;
    address user1;
    address user2;
    address tlsnVerifier;
    uint256 tlsnVerifierPrivateKey;
    
    uint256 constant GROUP_ID_0 = 1; // X account owner
    uint256 constant GROUP_ID_1 = 2; // Has Uber rides
    uint256 constant SCORE_100 = 100;
    uint256 constant SCORE_200 = 200;

    function setUp() public {
        owner = address(this);
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        (tlsnVerifier, tlsnVerifierPrivateKey) = makeAddrAndKey("tlsn-verifier");
        
        // Deploy Semaphore contracts
        semaphoreVerifier = new SemaphoreVerifier();
        semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));
        
        // Deploy registry
        registry = new CredentialRegistry(ISemaphore(address(semaphore)), tlsnVerifier);
        
        // Deploy IdCard with registry address
        idCard = new IdCard(registry);
        
        // Setup credential groups in registry
        registry.createCredentialGroup(GROUP_ID_0, SCORE_100);
        registry.createCredentialGroup(GROUP_ID_1, SCORE_200);
    }

    function testConstructor() public {
        assertEq(idCard.name(), "Bring ID Card");
        assertEq(idCard.symbol(), "Bring ID");
        assertEq(idCard.owner(), address(this));
        assertFalse(idCard.stopped());
        assertEq(address(idCard.registry()), address(registry));
    }

    function testToggleStop() public {
        assertFalse(idCard.stopped());
        
        idCard.toggleStop();
        assertTrue(idCard.stopped());
        
        idCard.toggleStop();
        assertFalse(idCard.stopped());
    }

    function testOnlyOwnerCanToggleStop() public {
        vm.prank(user1);
        vm.expectRevert();
        idCard.toggleStop();
        
        // Owner can toggle
        idCard.toggleStop();
        assertTrue(idCard.stopped());
    }

    function testTokenURIWithNonExistentId() public {
        uint256 tokenId = 999;
        vm.expectRevert("ID doesn't exist");
        idCard.tokenURI(tokenId);
    }

    function testTokenURIWithAddress() public {
        // This should revert because user1 has no ID yet
        vm.expectRevert("ID doesn't exist");
        idCard.tokenURI(user1);
    }

    function testValidClaim() public {
        // Setup user with commitment
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        // Add member to group
        bytes32 idHash = keccak256("test-user1");
        ICredentialRegistry.Attestation memory message = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: GROUP_ID_0,
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message, v, r, s);
        
        // Create proof
        uint256 scope = uint256(keccak256(abi.encode(address(idCard), 0)));
        
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
            credentialGroupId: GROUP_ID_0,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });
        
        // First claim should mint new NFT
        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](1);
        proofs[0] = proof;
        vm.prank(user1);
        idCard.claim(user1, proofs);
        
        assertEq(idCard.ownerOf(1), user1);
        uint256 score = idCard.IDs(1);
        assertEq(score, SCORE_100);
        
        // Test business logic: verify the verifications array contains exactly one element
        // Since verifications array cannot be accessed directly from public mapping,
        // we'll verify the business logic through the score and tokenURI
    }

    function testTokenURIGeneration() public {
        // First setup and claim an ID
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        bytes32 idHash = keccak256("test-user1");
        ICredentialRegistry.Attestation memory message = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: GROUP_ID_0,
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message, v, r, s);
        
        uint256 scope = uint256(keccak256(abi.encode(address(idCard), 0)));
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
            credentialGroupId: GROUP_ID_0,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });
        
        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](1);
        proofs[0] = proof;
        vm.prank(user1);
        idCard.claim(user1, proofs);
        
        // Test tokenURI generation - verifying the business logic of JSON generation
        string memory uri = idCard.tokenURI(1);
        assertTrue(bytes(uri).length > 0);
        
        // Verify the URI contains expected elements for single verification
        // According to Notes: tokenURI should handle single verification correctly
        assertTrue(bytes(uri).length > 100, "URI should be substantial JSON");
        
        // Also test tokenURI by address
        string memory uriByAddress = idCard.tokenURI(user1);
        assertEq(uri, uriByAddress, "URI by address should match URI by ID");
    }

    function testTokenURIValidJSON() public {
        // Setup and claim ID with single verification
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        bytes32 idHash = keccak256("test-user1");
        ICredentialRegistry.Attestation memory message = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: GROUP_ID_0,
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message, v, r, s);
        
        uint256 scope = uint256(keccak256(abi.encode(address(idCard), 0)));
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
            credentialGroupId: GROUP_ID_0,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });
        
        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](1);
        proofs[0] = proof;
        vm.prank(user1);
        idCard.claim(user1, proofs);
        
        // Get the generated tokenURI
        string memory uri = idCard.tokenURI(1);
        
        // Show the actual generated data URI
        console.log("=== Generated Data URI (Single Verification) ===");
        console.log(uri);
        console.log("=== End Data URI ===");
        
        // Test 1: Data URI format validation
        assertTrue(_contains(uri, "data:application/json;base64,"), "URI should start with data URI prefix");
        
        // Extract and decode the base64 JSON
        string memory jsonPart = _extractBase64Part(uri);
        string memory decodedJson = _decodeBase64(jsonPart);
        
        console.log("=== Decoded JSON ===");
        console.log(decodedJson);
        console.log("=== End Decoded JSON ===");
        
        // Test 2: Basic JSON structure validation
        bytes memory jsonBytes = bytes(decodedJson);
        assertTrue(jsonBytes.length > 0, "Decoded JSON should not be empty");
        assertTrue(jsonBytes[0] == 0x7b, "JSON should start with '{'"); // 0x7b = '{'
        assertTrue(jsonBytes[jsonBytes.length - 1] == 0x7d, "JSON should end with '}'"); // 0x7d = '}'
        
        // Test 3: Required JSON fields presence (check in decoded JSON)
        assertTrue(_contains(decodedJson, "\"name\":"), "JSON should contain name field");
        assertTrue(_contains(decodedJson, "\"image\":"), "JSON should contain image field");
        assertTrue(_contains(decodedJson, "\"external_url\":"), "JSON should contain external_url field");
        assertTrue(_contains(decodedJson, "\"description\":"), "JSON should contain description field");
        assertTrue(_contains(decodedJson, "\"attributes\":"), "JSON should contain attributes field");
        
        // Test 4: Specific values validation
        assertTrue(_contains(decodedJson, "\"Bring ID Card #1\""), "Should contain correct name");
        assertTrue(_contains(decodedJson, "\"https://www.bringid.org/100\""), "Should contain score in image URL");
        assertTrue(_contains(decodedJson, "\"https://www.bringid.org/\""), "Should contain external URL");
        assertTrue(_contains(decodedJson, "\"Bring ID is...\""), "Should contain description");
        
        // Test 5: Attributes structure validation
        assertTrue(_contains(decodedJson, "\"trait_type\": \"Verification\""), "Should contain verification trait type");
        assertTrue(_contains(decodedJson, "\"value\": \"X account owner\""), "Should contain correct verification name");
        
        // Test 6: JSON array structure for attributes
        assertTrue(_contains(decodedJson, "\"attributes\": ["), "Attributes should be an array");
        assertTrue(_contains(decodedJson, "}]"), "Should properly close attributes array");
        
        // Test 7: Proper JSON escaping (no unescaped quotes in values)
        // Count quotes to ensure they're properly balanced
        uint256 quoteCount = 0;
        for (uint256 i = 0; i < jsonBytes.length; i++) {
            if (jsonBytes[i] == 0x22) { // 0x22 = '"'
                quoteCount++;
            }
        }
        assertTrue(quoteCount % 2 == 0, "JSON should have balanced quotes");
        assertTrue(quoteCount >= 12, "Should have sufficient quoted fields");
    }

    function testTokenURIValidJSONMultipleVerifications() public {
        // Test JSON generation with multiple verifications to ensure array handling is correct
        
        // Setup user1 with first credential
        uint256 commitmentKey1 = 12345;
        uint256 commitment1 = TestUtils.semaphoreCommitment(commitmentKey1);
        
        bytes32 idHash1 = keccak256("test-user1-group0");
        ICredentialRegistry.Attestation memory message1 = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: GROUP_ID_0,
            idHash: idHash1,
            semaphoreIdentityCommitment: commitment1
        });
        
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message1)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message1, v1, r1, s1);
        
        // First claim
        uint256 scope1 = uint256(keccak256(abi.encode(address(idCard), 0)));
        uint256[] memory commitments1 = new uint256[](1);
        commitments1[0] = commitment1;
        
        (
            uint256 merkleTreeDepth1,
            uint256 merkleTreeRoot1,
            uint256 nullifier1,
            uint256 messageHash1,
            uint256[8] memory points1
        ) = TestUtils.semaphoreProof(commitmentKey1, scope1, commitments1);
        
        ICredentialRegistry.CredentialGroupProof memory proof1 = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: GROUP_ID_0,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth1,
                merkleTreeRoot: merkleTreeRoot1,
                nullifier: nullifier1,
                message: messageHash1,
                scope: scope1,
                points: points1
            })
        });
        
        ICredentialRegistry.CredentialGroupProof[] memory proofs1 = new ICredentialRegistry.CredentialGroupProof[](1);
        proofs1[0] = proof1;
        vm.prank(user1);
        idCard.claim(user1, proofs1);
        
        // Setup second credential
        uint256 commitmentKey2 = 67890;
        uint256 commitment2 = TestUtils.semaphoreCommitment(commitmentKey2);
        
        bytes32 idHash2 = keccak256("test-user1-group1");
        ICredentialRegistry.Attestation memory message2 = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: GROUP_ID_1,
            idHash: idHash2,
            semaphoreIdentityCommitment: commitment2
        });
        
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message2)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message2, v2, r2, s2);
        
        // Second claim
        uint256 scope2 = uint256(keccak256(abi.encode(address(idCard), 0)));
        uint256[] memory commitments2 = new uint256[](1);
        commitments2[0] = commitment2;
        
        (
            uint256 merkleTreeDepth2,
            uint256 merkleTreeRoot2,
            uint256 nullifier2,
            uint256 messageHash2,
            uint256[8] memory points2
        ) = TestUtils.semaphoreProof(commitmentKey2, scope2, commitments2);
        
        ICredentialRegistry.CredentialGroupProof memory proof2 = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: GROUP_ID_1,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth2,
                merkleTreeRoot: merkleTreeRoot2,
                nullifier: nullifier2,
                message: messageHash2,
                scope: scope2,
                points: points2
            })
        });
        
        ICredentialRegistry.CredentialGroupProof[] memory proofs2 = new ICredentialRegistry.CredentialGroupProof[](1);
        proofs2[0] = proof2;
        vm.prank(user1);
        idCard.claim(user1, proofs2);
        
        // Get the generated tokenURI with multiple verifications
        string memory uri = idCard.tokenURI(1);
        
        // Show the actual generated data URI for multiple verifications
        console.log("=== Generated Data URI (Multiple Verifications) ===");
        console.log(uri);
        console.log("=== End Data URI ===");
        
        // Extract and decode the base64 JSON
        string memory jsonPart = _extractBase64Part(uri);
        string memory decodedJson = _decodeBase64(jsonPart);
        
        console.log("=== Decoded JSON (Multiple Verifications) ===");
        console.log(decodedJson);
        console.log("=== End Decoded JSON ===");
        
        // Test JSON structure with multiple attributes
        assertTrue(_contains(decodedJson, "\"https://www.bringid.org/300\""), "Should contain combined score (100+200)");
        
        // Should contain both verification names
        assertTrue(_contains(decodedJson, "\"X account owner\""), "Should contain first verification name");
        assertTrue(_contains(decodedJson, "\"Has Uber rides\""), "Should contain second verification name");
        
        // Test proper comma separation between attributes
        assertTrue(_contains(decodedJson, "\"},"), "Should have comma between attributes");
        assertTrue(_contains(decodedJson, "\"}]"), "Should properly close last attribute and array");
        
        // Verify no trailing comma after last attribute
        assertFalse(_contains(decodedJson, "\"},]"), "Should not have trailing comma in attributes array");
        
        // Count verification attributes (should be exactly 2)
        uint256 verificationCount = _countOccurrences(decodedJson, "\"trait_type\": \"Verification\"");
        assertEq(verificationCount, 2, "Should have exactly 2 verification attributes");
    }

    // Helper function to check if a string contains a substring
    function _contains(string memory str, string memory substr) internal pure returns (bool) {
        bytes memory strBytes = bytes(str);
        bytes memory substrBytes = bytes(substr);
        
        if (substrBytes.length > strBytes.length) return false;
        
        for (uint256 i = 0; i <= strBytes.length - substrBytes.length; i++) {
            bool found = true;
            for (uint256 j = 0; j < substrBytes.length; j++) {
                if (strBytes[i + j] != substrBytes[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return true;
        }
        return false;
    }

    // Helper function to count occurrences of a substring
    function _countOccurrences(string memory str, string memory substr) internal pure returns (uint256) {
        bytes memory strBytes = bytes(str);
        bytes memory substrBytes = bytes(substr);
        uint256 count = 0;
        
        if (substrBytes.length > strBytes.length) return 0;
        
        for (uint256 i = 0; i <= strBytes.length - substrBytes.length; i++) {
            bool found = true;
            for (uint256 j = 0; j < substrBytes.length; j++) {
                if (strBytes[i + j] != substrBytes[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                count++;
                i += substrBytes.length - 1; // Skip ahead to avoid overlapping matches
            }
        }
        return count;
    }

    // Helper function to extract base64 part from data URI
    function _extractBase64Part(string memory dataUri) internal pure returns (string memory) {
        bytes memory dataUriBytes = bytes(dataUri);
        bytes memory prefix = bytes("data:application/json;base64,");
        
        require(dataUriBytes.length >= prefix.length, "Invalid data URI format");
        
        // Verify prefix matches
        for (uint256 i = 0; i < prefix.length; i++) {
            require(dataUriBytes[i] == prefix[i], "Invalid data URI prefix");
        }
        
        // Extract everything after the prefix
        bytes memory base64Part = new bytes(dataUriBytes.length - prefix.length);
        for (uint256 i = 0; i < base64Part.length; i++) {
            base64Part[i] = dataUriBytes[prefix.length + i];
        }
        
        return string(base64Part);
    }

    // Helper function to decode base64 string (simplified for testing)
    function _decodeBase64(string memory base64Str) internal pure returns (string memory) {
        // For testing purposes, we'll use a simplified approach
        // In practice, you'd want a proper base64 decoder
        // Since we're testing the contract's Base64.encode output, we can reverse it
        
        bytes memory base64Bytes = bytes(base64Str);
        
        // Base64 decoding lookup table
        bytes memory alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        uint256[] memory decode = new uint256[](128);
        
        // Initialize decode table
        for (uint256 i = 0; i < alphabet.length; i++) {
            decode[uint256(uint8(alphabet[i]))] = i;
        }
        
        // Calculate output length
        uint256 outputLength = (base64Bytes.length * 3) / 4;
        if (base64Bytes.length > 0 && base64Bytes[base64Bytes.length - 1] == 0x3D) outputLength--; // Remove padding
        if (base64Bytes.length > 1 && base64Bytes[base64Bytes.length - 2] == 0x3D) outputLength--; // Remove padding
        
        bytes memory result = new bytes(outputLength);
        uint256 resultIndex = 0;
        
        // Decode 4 characters at a time
        for (uint256 i = 0; i < base64Bytes.length; i += 4) {
            uint256 a = base64Bytes[i] != 0x3D ? decode[uint256(uint8(base64Bytes[i]))] : 0;
            uint256 b = i + 1 < base64Bytes.length && base64Bytes[i + 1] != 0x3D ? decode[uint256(uint8(base64Bytes[i + 1]))] : 0;
            uint256 c = i + 2 < base64Bytes.length && base64Bytes[i + 2] != 0x3D ? decode[uint256(uint8(base64Bytes[i + 2]))] : 0;
            uint256 d = i + 3 < base64Bytes.length && base64Bytes[i + 3] != 0x3D ? decode[uint256(uint8(base64Bytes[i + 3]))] : 0;
            
            uint256 triple = (a << 18) | (b << 12) | (c << 6) | d;
            
            if (resultIndex < result.length) result[resultIndex++] = bytes1(uint8(triple >> 16));
            if (resultIndex < result.length) result[resultIndex++] = bytes1(uint8(triple >> 8));
            if (resultIndex < result.length) result[resultIndex++] = bytes1(uint8(triple));
        }
        
        return string(result);
    }

    function testMultipleClaimsScenario() public {
        // Setup user1 with first credential
        uint256 commitmentKey1 = 12345;
        uint256 commitment1 = TestUtils.semaphoreCommitment(commitmentKey1);
        
        bytes32 idHash1 = keccak256("test-user1-group0");
        ICredentialRegistry.Attestation memory message1 = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: GROUP_ID_0,
            idHash: idHash1,
            semaphoreIdentityCommitment: commitment1
        });
        
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message1)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message1, v1, r1, s1);
        
        // First claim
        uint256 scope1 = uint256(keccak256(abi.encode(address(idCard), 0)));
        uint256[] memory commitments1 = new uint256[](1);
        commitments1[0] = commitment1;
        
        (
            uint256 merkleTreeDepth1,
            uint256 merkleTreeRoot1,
            uint256 nullifier1,
            uint256 messageHash1,
            uint256[8] memory points1
        ) = TestUtils.semaphoreProof(commitmentKey1, scope1, commitments1);
        
        ICredentialRegistry.CredentialGroupProof memory proof1 = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: GROUP_ID_0,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth1,
                merkleTreeRoot: merkleTreeRoot1,
                nullifier: nullifier1,
                message: messageHash1,
                scope: scope1,
                points: points1
            })
        });
        
        ICredentialRegistry.CredentialGroupProof[] memory proofs1 = new ICredentialRegistry.CredentialGroupProof[](1);
        proofs1[0] = proof1;
        vm.prank(user1);
        idCard.claim(user1, proofs1);
        
        // Setup user1 with second credential (different commitment key and idHash)
        uint256 commitmentKey2 = 67890;
        uint256 commitment2 = TestUtils.semaphoreCommitment(commitmentKey2);
        
        bytes32 idHash2 = keccak256("test-user1-group1");
        ICredentialRegistry.Attestation memory message2 = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: GROUP_ID_1,
            idHash: idHash2,
            semaphoreIdentityCommitment: commitment2
        });
        
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message2)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message2, v2, r2, s2);
        
        // Second claim should update existing NFT
        uint256 scope2 = uint256(keccak256(abi.encode(address(idCard), 0)));
        uint256[] memory commitments2 = new uint256[](1);
        commitments2[0] = commitment2;
        
        (
            uint256 merkleTreeDepth2,
            uint256 merkleTreeRoot2,
            uint256 nullifier2,
            uint256 messageHash2,
            uint256[8] memory points2
        ) = TestUtils.semaphoreProof(commitmentKey2, scope2, commitments2);
        
        ICredentialRegistry.CredentialGroupProof memory proof2 = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: GROUP_ID_1,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth2,
                merkleTreeRoot: merkleTreeRoot2,
                nullifier: nullifier2,
                message: messageHash2,
                scope: scope2,
                points: points2
            })
        });
        
        ICredentialRegistry.CredentialGroupProof[] memory proofs2 = new ICredentialRegistry.CredentialGroupProof[](1);
        proofs2[0] = proof2;
        vm.prank(user1);
        idCard.claim(user1, proofs2);
        
        // Check accumulated score and verifications business logic
        uint256 score = idCard.IDs(1);
        assertEq(score, SCORE_100 + SCORE_200);
        
        // Verify verifications through tokenURI since array is not directly accessible
        string memory uri = idCard.tokenURI(1);
        // Extract and decode JSON to verify multiple verifications
        string memory jsonPart = _extractBase64Part(uri);
        string memory decodedJson = _decodeBase64(jsonPart);
        assertTrue(_contains(decodedJson, "\"X account owner\""), "Should contain first verification");
        assertTrue(_contains(decodedJson, "\"Has Uber rides\""), "Should contain second verification");
    }

    function testStoppedModifier() public {
        idCard.toggleStop();
        
        // Setup user with commitment
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        bytes32 idHash = keccak256("test-user1");
        ICredentialRegistry.Attestation memory message = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: GROUP_ID_0,
            idHash: idHash,
            semaphoreIdentityCommitment: commitment
        });
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message, v, r, s);
        
        uint256 scope = uint256(keccak256(abi.encode(address(idCard), 0)));
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
            credentialGroupId: GROUP_ID_0,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth,
                merkleTreeRoot: merkleTreeRoot,
                nullifier: nullifier,
                message: messageHash,
                scope: scope,
                points: points
            })
        });

        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](1);
        proofs[0] = proof;
        vm.prank(user1);
        vm.expectRevert("Campaign stopped");
        idCard.claim(user1, proofs);
    }

    function testClaimWithInvalidProof() public {
        // Create proof without adding member to group
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        
        uint256 scope = uint256(keccak256(abi.encode(address(idCard), 0)));
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
            credentialGroupId: GROUP_ID_0,
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
        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](1);
        proofs[0] = proof;
        vm.prank(user1);
        vm.expectRevert();
        idCard.claim(user1, proofs);
    }

    function testDuplicateVerifications() public {
        // Test if a user can claim the same credential group twice
        // According to Notes: CredentialRegistry has nonce to prevent duplicate claims
        
        // Setup user with first commitment for GROUP_ID_0
        uint256 commitmentKey1 = 12345;
        uint256 commitment1 = TestUtils.semaphoreCommitment(commitmentKey1);
        
        bytes32 idHash1 = keccak256("test-user1-attempt1");
        ICredentialRegistry.Attestation memory message1 = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: GROUP_ID_0,
            idHash: idHash1,
            semaphoreIdentityCommitment: commitment1
        });
        
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message1)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message1, v1, r1, s1);
        
        // First claim should succeed
        uint256 scope1 = uint256(keccak256(abi.encode(address(idCard), 0)));
        uint256[] memory commitments1 = new uint256[](1);
        commitments1[0] = commitment1;
        
        (
            uint256 merkleTreeDepth1,
            uint256 merkleTreeRoot1,
            uint256 nullifier1,
            uint256 messageHash1,
            uint256[8] memory points1
        ) = TestUtils.semaphoreProof(commitmentKey1, scope1, commitments1);
        
        ICredentialRegistry.CredentialGroupProof memory proof1 = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: GROUP_ID_0,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth1,
                merkleTreeRoot: merkleTreeRoot1,
                nullifier: nullifier1,
                message: messageHash1,
                scope: scope1,
                points: points1
            })
        });
        
        ICredentialRegistry.CredentialGroupProof[] memory proofs1 = new ICredentialRegistry.CredentialGroupProof[](1);
        proofs1[0] = proof1;
        vm.prank(user1);
        idCard.claim(user1, proofs1);
        
        // Verify first claim succeeded
        uint256 score = idCard.IDs(1);
        assertEq(score, SCORE_100);
        
        // Now try to claim the same GROUP_ID_0 again with a different commitment
        uint256 commitmentKey2 = 67890;
        uint256 commitment2 = TestUtils.semaphoreCommitment(commitmentKey2);
        
        // Same idHash - this should be prevented by nonce
        bytes32 idHash2 = keccak256("test-user1-attempt1"); // Same idHash as before
        ICredentialRegistry.Attestation memory message2 = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: GROUP_ID_0, // Same group
            idHash: idHash2, // Same idHash
            semaphoreIdentityCommitment: commitment2 // Different commitment
        });
        
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message2)).toEthSignedMessageHash()
        );
        
        // This should fail due to nonce reuse (same registry + credentialGroupId + idHash)
        vm.expectRevert("Nonce is used");
        registry.joinGroup(message2, v2, r2, s2);
    }


    function testMultipleUsers() public {
        // Setup user1
        uint256 commitmentKey1 = 12345;
        uint256 commitment1 = TestUtils.semaphoreCommitment(commitmentKey1);
        
        bytes32 idHash1 = keccak256("test-user1");
        ICredentialRegistry.Attestation memory message1 = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: GROUP_ID_0,
            idHash: idHash1,
            semaphoreIdentityCommitment: commitment1
        });
        
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message1)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message1, v1, r1, s1);
        
        // Setup user2
        uint256 commitmentKey2 = 67890;
        uint256 commitment2 = TestUtils.semaphoreCommitment(commitmentKey2);
        
        bytes32 idHash2 = keccak256("test-user2");
        ICredentialRegistry.Attestation memory message2 = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: GROUP_ID_0,
            idHash: idHash2,
            semaphoreIdentityCommitment: commitment2
        });
        
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message2)).toEthSignedMessageHash()
        );
        
        registry.joinGroup(message2, v2, r2, s2);
        
        // Create proofs
        uint256 scope1 = uint256(keccak256(abi.encode(address(idCard), 0)));
        uint256 scope2 = uint256(keccak256(abi.encode(address(idCard), 0)));
        
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
        ) = TestUtils.semaphoreProof(commitmentKey1, scope1, commitments1);
        
        (
            uint256 merkleTreeDepth2,
            uint256 merkleTreeRoot2,
            uint256 nullifier2,
            uint256 messageHash2,
            uint256[8] memory points2
        ) = TestUtils.semaphoreProof(commitmentKey2, scope2, commitments2);
        
        ICredentialRegistry.CredentialGroupProof memory proof1 = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: GROUP_ID_0,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth1,
                merkleTreeRoot: merkleTreeRoot1,
                nullifier: nullifier1,
                message: messageHash1,
                scope: scope1,
                points: points1
            })
        });
        
        ICredentialRegistry.CredentialGroupProof memory proof2 = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: GROUP_ID_0,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: merkleTreeDepth2,
                merkleTreeRoot: merkleTreeRoot2,
                nullifier: nullifier2,
                message: messageHash2,
                scope: scope2,
                points: points2
            })
        });
        
        // First claim
        ICredentialRegistry.CredentialGroupProof[] memory proofs1 = new ICredentialRegistry.CredentialGroupProof[](1);
        proofs1[0] = proof1;
        vm.prank(user1);
        idCard.claim(user1, proofs1);
        assertEq(idCard.ownerOf(1), user1);
        
        // Second claim
        ICredentialRegistry.CredentialGroupProof[] memory proofs2 = new ICredentialRegistry.CredentialGroupProof[](1);
        proofs2[0] = proof2;
        vm.prank(user2);
        idCard.claim(user2, proofs2);
        assertEq(idCard.ownerOf(2), user2);
        
        // Check both IDs exist
        uint256 score1 = idCard.IDs(1);
        uint256 score2 = idCard.IDs(2);
        assertEq(score1, SCORE_100);
        assertEq(score2, SCORE_100);
    }
}