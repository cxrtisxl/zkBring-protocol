// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

interface IzkBringRegistry {
    struct SemaphoreProof {
        uint256 merkleTreeDepth;
        uint256 merkleTreeRoot;
        uint256 nullifier;
        uint256 message;
        uint256[8] points;
    }

    function validateProof(uint256 verificationId, SemaphoreProof memory proof) external;
}
