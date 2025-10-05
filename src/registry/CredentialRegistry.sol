// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "./Events.sol";
import {ICredentialRegistry} from "./ICredentialRegistry.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {Ownable2Step} from "openzeppelin/access/Ownable2Step.sol";

contract CredentialRegistry is ICredentialRegistry, Ownable2Step {
    using ECDSA for bytes32;

    ISemaphore public immutable SEMAPHORE;
    address public TLSNVerifier;
    mapping(uint256 credentialGroupId => CredentialGroup) public credentialGroups;
    mapping(bytes32 nullifier => bool isConsumed) private _nonceUsed;

    constructor(ISemaphore semaphore_, address TLSNVerifier_) {
        require(TLSNVerifier_ != address(0), "Invalid TLSN Verifier address");
        SEMAPHORE = semaphore_;
        TLSNVerifier = TLSNVerifier_;
    }

    function credentialGroupIsActive(
        uint256 credentialGroupId_
    ) public view returns (bool) {
        return credentialGroups[credentialGroupId_].status == CredentialGroupStatus.ACTIVE;
    }

    function credentialGroupScore(
        uint256 credentialGroupId_
    ) public view returns (uint256) {
        return credentialGroups[credentialGroupId_].score;
    }

    // @notice signature can be reused across all networks
    function joinGroup(
        Attestation memory attestation_,
        bytes memory signature_
    ) public {
        require(signature_.length == 65, "Bad signature length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(signature_, 0x20))
            s := mload(add(signature_, 0x40))
            v := byte(0, mload(add(signature_, 0x60)))
        }
        joinGroup(attestation_, v, r, s);
    }

    function joinGroup(
        Attestation memory attestation_,
        uint8 v, bytes32 r, bytes32 s
    ) public {
        CredentialGroup memory _credentialGroup = credentialGroups[attestation_.credentialGroupId];
        // excludes semaphoreIdentityCommitment ensuring one credential for credentialGroupId + idHash (user account ID).
        bytes32 nonce = keccak256(
            abi.encode(
                attestation_.registry,
                attestation_.credentialGroupId,
                attestation_.idHash
            )
        );

        require(_credentialGroup.status == CredentialGroupStatus.ACTIVE, "Credential group is inactive");
        require(attestation_.registry == address(this), "Wrong attestation message");
        require(!_nonceUsed[nonce], "Nonce is used");

        (address signer,) = keccak256(
            abi.encode(attestation_)
        ).toEthSignedMessageHash().tryRecover(v, r, s);

        require(signer == TLSNVerifier, "Invalid TLSN Verifier signature");

        _nonceUsed[nonce] = true;
        SEMAPHORE.addMember(_credentialGroup.semaphoreGroupId, attestation_.semaphoreIdentityCommitment);
        emit CredentialAdded(attestation_.credentialGroupId, attestation_.semaphoreIdentityCommitment);
    }

    // @notice Validates Semaphore proof
    // @dev `context_` parameter here is concatenated with sender address
    function validateProof(
        uint256 context_,
        CredentialGroupProof calldata proof_
    ) public {
        CredentialGroup memory _credentialGroup = credentialGroups[proof_.credentialGroupId];
        require(_credentialGroup.status == CredentialGroupStatus.ACTIVE, "Credential group is inactive");
        require(
            proof_.semaphoreProof.scope == uint256(keccak256(abi.encode(msg.sender, context_))),
            "Wrong scope"
        );

        SEMAPHORE.validateProof(_credentialGroup.semaphoreGroupId, proof_.semaphoreProof);
        emit ProofValidated(proof_.credentialGroupId);
    }

    // @dev score should be used only for the score preview
    // @notice score doesn't check proofs' nullifiers
    // @notice score doesn't check duplicate proofs
    // @notice score reverts if any proof for an active Credential Group is invalid
    function score(
        CredentialGroupProof[] calldata proofs_,
        bool skipInactive_
    ) public view returns (uint256 _score) {
        _score = 0;
        for (uint256 i = 0; i < proofs_.length; i++) {
            CredentialGroup memory _credentialGroup = credentialGroups[proofs_[i].credentialGroupId];
            if (_credentialGroup.status != CredentialGroupStatus.ACTIVE) {
                if (skipInactive_) {
                    continue;
                }
                revert("Credential group is inactive");
            }
            require(
                _verifyProof(_credentialGroup.semaphoreGroupId, proofs_[i].semaphoreProof),
                "Invalid proof"
            );
            _score += _credentialGroup.score;
        }
    }

    function verifyProof(
        CredentialGroupProof calldata proof_
    ) public view returns (bool) {
        CredentialGroup memory _credentialGroup = credentialGroups[proof_.credentialGroupId];
        require(_credentialGroup.status == CredentialGroupStatus.ACTIVE, "Credential group is inactive");
        return _verifyProof(_credentialGroup.semaphoreGroupId, proof_.semaphoreProof);
    }

    function _verifyProof(
        uint256 groupId_,
        ISemaphore.SemaphoreProof calldata semaphoreProof_
    ) private view returns(bool) {
        return SEMAPHORE.verifyProof(groupId_, semaphoreProof_);
    }

    // ONLY OWNER //

    function createCredentialGroup(
        uint256 credentialGroupId_,
        uint256 score_
    ) public onlyOwner {
        require(credentialGroupId_ > 0, "Credential group ID cannot equal zero");
        require(credentialGroups[credentialGroupId_].status == CredentialGroupStatus.UNDEFINED, "Credential group exists");
        CredentialGroup memory _credentialGroup = CredentialGroup(
            score_,
            SEMAPHORE.createGroup(),
            ICredentialRegistry.CredentialGroupStatus.ACTIVE
        );
        credentialGroups[credentialGroupId_] = _credentialGroup;
        emit CredentialGroupCreated(credentialGroupId_, _credentialGroup);
    }

    // TODO: Suspend credential group

    function setVerifier(
        address TLSNVerifier_
    ) public onlyOwner {
        require(TLSNVerifier_ != address(0), "Invalid TLSN Verifier address");
        TLSNVerifier = TLSNVerifier_;
        emit TLSNVerifierSet(TLSNVerifier_);
    }
}
