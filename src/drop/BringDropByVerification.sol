// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IBringRegistry} from "../registry/IBringRegistry.sol";
import {BringDropBase} from "./BringDropBase.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";

contract BringDropByVerification is BringDropBase {
    uint256 public immutable verificationId;

    constructor(
        uint256 verificationId_,
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
        require(registry_.verificationIsActive(verificationId_), "Verification is inactive");
        verificationId = verificationId_;
    }

    function claim(
        address to,
        IBringRegistry.VerificationProof calldata proof
    ) public notStopped notExpired {
        require(proof.verificationId == verificationId, "Wrong Verification");
        require(claims < maxClaims, "All claims exhausted");

        claims++;
        registry.validateProof(0, proof);

        require(
            token.transfer(to, amount),
            "Token transfer failed"
        );
    }
}
