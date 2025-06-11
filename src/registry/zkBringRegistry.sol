// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "./Events.sol";
import {IzkBringRegistry} from "./IzkBringRegistry.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {Ownable2Step} from "openzeppelin/access/Ownable2Step.sol";

contract zkBringRegistry is IzkBringRegistry, Ownable2Step {
    using ECDSA for bytes32;

    ISemaphore public immutable SEMAPHORE;
    address public TLSNVerifier;
    mapping(uint256 verifivationId => uint256 semaphoreGroupId) private _semaphoreGroupIds;
    mapping(bytes32 nullifier => bool isConsumed) private _nullifierConsumed;

    constructor(ISemaphore semaphore_, address TLSNVerifier_) {
        SEMAPHORE = semaphore_;
        TLSNVerifier = TLSNVerifier_;
    }

    function joinGroup(
        TLSNVerifierMessage memory verifierMessage_,
        bytes memory signature_
    ) public returns (bool success) {
        uint256 semaphoreGroupId = _semaphoreGroupIds[verifierMessage_.verificationId];
        bytes32 nullifier = keccak256(
            abi.encode(
                verifierMessage_.registry,
                verifierMessage_.verificationId,
                verifierMessage_.idHash
            )
        );

        require(semaphoreGroupId != 0, "Verification doesn't exist");
        require(verifierMessage_.registry == address(this), "Wrong Verifier message");
        require(!_nullifierConsumed[nullifier], "Nullifier is consumed");

        (address signer,) = keccak256(
            abi.encode(verifierMessage_)
        ).toEthSignedMessageHash().tryRecover(signature_);

        if (signer == TLSNVerifier) {
            SEMAPHORE.addMember(semaphoreGroupId, verifierMessage_.semaphoreIdentityCommitment);
            _nullifierConsumed[nullifier] = true;
            success = true;
        }
        return success;
    }

    function validateProof(
        uint256 verificationId_,
        SemaphoreProof calldata proof_
    ) public {
        uint256 semaphoreGroupId = _semaphoreGroupIds[verificationId_];
        require(semaphoreGroupId != 0, "Verification doesn't exist");
        ISemaphore.SemaphoreProof memory proof = ISemaphore.SemaphoreProof(
            proof_.merkleTreeDepth,
            proof_.merkleTreeRoot,
            proof_.nullifier,
            proof_.message,
            uint256(keccak256(abi.encode(msg.sender))),
            proof_.points
        );
        SEMAPHORE.validateProof(semaphoreGroupId, proof);
    }

    // ONLY OWNER //

    function newVerification(
        uint256 verificationId
    ) public onlyOwner {
        require(_semaphoreGroupIds[verificationId] == 0, "Verification exists");
        _semaphoreGroupIds[verificationId] = SEMAPHORE.createGroup();
        emit VerificationCreated(verificationId);
    }

    function setVerifier(
        address TLSNVerifier_
    ) public onlyOwner {
        TLSNVerifier = TLSNVerifier_;
        emit TLSNVerifierSet(TLSNVerifier_);
    }
}
