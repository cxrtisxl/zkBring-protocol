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
    mapping(uint256 verifivationId => Verification) public verifications;
    mapping(bytes32 nullifier => bool isConsumed) private _nonceUsed;

    constructor(ISemaphore semaphore_, address TLSNVerifier_) {
        SEMAPHORE = semaphore_;
        TLSNVerifier = TLSNVerifier_;
    }

    function joinGroup(
        TLSNVerifierMessage memory verifierMessage_,
        bytes memory signature_
    ) public {
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(signature_, 0x20))
            s := mload(add(signature_, 0x40))
            v := byte(0, mload(add(signature_, 0x60)))
        }
        joinGroup(verifierMessage_, v, r, s);
    }

    function joinGroup(
        TLSNVerifierMessage memory verifierMessage_,
        uint8 v, bytes32 r, bytes32 s
    ) public {
        Verification memory _verification = verifications[verifierMessage_.verificationId];
        bytes32 nonce = keccak256(
            abi.encode(
                verifierMessage_.registry,
                verifierMessage_.verificationId,
                verifierMessage_.idHash
            )
        );

        require(_verification.status == VerificationStatus.ACTIVE, "Verification is inactive");
        require(verifierMessage_.registry == address(this), "Wrong Verifier message");
        require(!_nonceUsed[nonce], "Nonce is used");

        (address signer,) = keccak256(
            abi.encode(verifierMessage_)
        ).toEthSignedMessageHash().tryRecover(v, r, s);

        require(signer == TLSNVerifier, "Invalid TLSN Verifier signature");

        SEMAPHORE.addMember(_verification.semaphoreGroupId, verifierMessage_.semaphoreIdentityCommitment);
        _nonceUsed[nonce] = true;
        emit Verified(verifierMessage_.verificationId, verifierMessage_.semaphoreIdentityCommitment);
    }

    // @notice Validates Semaphore proof
    // @dev `context_` parameter here is concatenated with sender address
    function validateProof(
        uint256 context_,
        VerificationProof calldata proof_
    ) public {
        Verification memory _verification = verifications[proof_.verificationId];
        require(_verification.status == VerificationStatus.ACTIVE, "Verification is inactive");
        require(
            proof_.semaphoreProof.scope == uint256(keccak256(abi.encode(msg.sender, context_))),
            "Wrong scope"
        );

        SEMAPHORE.validateProof(_verification.semaphoreGroupId, proof_.semaphoreProof);
        emit Proved(proof_.verificationId);
    }

    function score(
        VerificationProof[] calldata proofs_,
        bool skipInactive_
    ) public view returns (uint256 _score){
        _score = 0;
        for (uint256 i = 0; i < proofs_.length; i++) {
            Verification memory _verification = verifications[proofs_[i].verificationId];
            if (_verification.status != VerificationStatus.ACTIVE) {
                if (skipInactive_) {
                    continue;
                }
                // TODO custom error should return the inactive verification ID
                revert("Verification is inactive");
            }
            _verifyProof(_verification.semaphoreGroupId, proofs_[i].semaphoreProof);
            _score += _verification.score;
        }
    }

    function verifyProof(
        VerificationProof calldata proof_
    ) public view returns (bool) {
        Verification memory _verification = verifications[proof_.verificationId];
        require(_verification.status == VerificationStatus.ACTIVE, "Verification is inactive");
        return _verifyProof(_verification.semaphoreGroupId, proof_.semaphoreProof);
    }

    function _verifyProof(
        uint256 groupId_,
        ISemaphore.SemaphoreProof calldata semaphoreProof_
    ) private view returns(bool) {
        return SEMAPHORE.verifyProof(groupId_, semaphoreProof_);
    }

    // ONLY OWNER //

    function newVerification(
        uint256 verificationId_,
        uint256 score_
    ) public onlyOwner {
        require(verifications[verificationId_].status == VerificationStatus.UNDEFINED, "Verification exists");
        Verification memory _verification = Verification(
            score_,
            SEMAPHORE.createGroup(),
            IzkBringRegistry.VerificationStatus.ACTIVE
        );
        verifications[verificationId_] = _verification;
        emit VerificationCreated(verificationId_, _verification);
    }

    // TODO: Suspend verification

    function setVerifier(
        address TLSNVerifier_
    ) public onlyOwner {
        TLSNVerifier = TLSNVerifier_;
        emit TLSNVerifierSet(TLSNVerifier_);
    }
}
