// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IzkBringRegistry} from "../registry/IzkBringRegistry.sol";
import {zkBringDropBase} from "./zkBringDropBase.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";

contract zkBringDropByVerification is zkBringDropBase {
    uint256 public immutable verificationId;

    constructor(
        uint256 verificationId_,
        IzkBringRegistry registry_,
        address creator_,
        IERC20 token_,
        uint256 amount_,
        uint256 maxClaims_,
        uint256 expiration_,
        string memory metadataIpfsHash_,
        IERC20 bringToken_
    )
        zkBringDropBase(
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
        verificationId = verificationId_;
    }

    function claim(
        IzkBringRegistry.VerificationProof calldata proof,
        address to
    ) public {
        require(proof.verificationId == verificationId, "Wrong Verification");
        require(claims < maxClaims, "All claims exhausted");

        registry.validateProof(0, proof);
        claims++;

        require(
            token.transfer(to, amount),
            "Token transfer failed"
        );
    }
}
