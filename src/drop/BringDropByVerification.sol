// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ICredentialRegistry} from "../registry/ICredentialRegistry.sol";
import {BringDropBase} from "./BringDropBase.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";

contract BringDropByVerification is BringDropBase {
    uint256 public immutable credentialGroupId;

    constructor(
        uint256 credentialGroupId_,
        ICredentialRegistry registry_,
        address creator_,
        IERC20 token_,
        uint256 amount_,
        uint256 maxClaims_,
        uint256 expiration_,
        string memory metadataIpfsHash_,
        IERC20 bringToken_
    )
        BringDropBase(
            registry_,
            creator_,
            token_,
            amount_,
            maxClaims_,
            expiration_,
            metadataIpfsHash_,
            bringToken_
        )
    {
        require(registry_.credentialGroupIsActive(credentialGroupId_), "Credential group is inactive");
        credentialGroupId = credentialGroupId_;
    }

    function claim(
        address to,
        ICredentialRegistry.CredentialGroupProof calldata proof
    ) public notStopped notExpired {
        require(proof.credentialGroupId == credentialGroupId, "Wrong credential group");
        require(claims < maxClaims, "All claims exhausted");

        claims++;
        registry.validateProof(0, proof);

        require(
            token.transfer(to, amount),
            "Token transfer failed"
        );
    }
}
