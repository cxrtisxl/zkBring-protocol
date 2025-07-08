// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";

interface IBringRegistry {
    enum VerificationStatus{UNDEFINED, ACTIVE, SUSPENDED}

    struct Verification {
        uint256 score;
        uint256 semaphoreGroupId;
        VerificationStatus status;
    }

    struct VerificationProof {
        uint256 verificationId;
        ISemaphore.SemaphoreProof semaphoreProof;
    }

    struct TLSNVerifierMessage {
        address registry;
        uint256 verificationId;
        bytes32 idHash;
        uint256 semaphoreIdentityCommitment;
    }

    function score(VerificationProof[] calldata proofs, bool skipInactive) external view returns (uint256);
    function validateProof(uint256 context, VerificationProof calldata proof) external;
    function verificationIsActive(uint256 verificationId_) external view returns (bool);
}
