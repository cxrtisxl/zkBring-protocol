// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";

interface IzkBringRegistry {
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

    function validateProof(uint256 context, VerificationProof calldata proof) external;
}
