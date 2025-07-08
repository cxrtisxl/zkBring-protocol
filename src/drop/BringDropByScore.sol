// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IBringRegistry} from "../registry/IBringRegistry.sol";
import {BringDropBase} from "./BringDropBase.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";

contract BringDropByScore is BringDropBase {
    uint256 public immutable scoreThreshold;

    constructor(
        uint256 scoreThreshold_,
        IBringRegistry registry_,
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
        scoreThreshold = scoreThreshold_;
    }

    function claim(
        IBringRegistry.VerificationProof[] calldata proofs
    ) public notStopped notExpired {
        require(claims < maxClaims, "All claims exhausted");
        uint256 totalScore = registry.score(proofs, true);
        require(totalScore > scoreThreshold, "Insufficient score");

        claims++;
        for (uint256 i; i < proofs.length; i++) {
            registry.validateProof(0, proofs[i]);
        }
        require(
            token.transfer(msg.sender, amount),
            "Token transfer failed"
        );
    }
}
