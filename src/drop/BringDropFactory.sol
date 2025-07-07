// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {Ownable2Step} from "openzeppelin/access/Ownable2Step.sol";
import {IBringRegistry} from "../registry/IBringRegistry.sol";
import {BringDropByScore} from "./BringDropByScore.sol";
import "./Events.sol";

contract BringDropFactory is Ownable2Step {
    // Fee 0.01 percentage (e.g., 5 means 0.05%)
    uint256 public fee;
    address public feeRecipient;
    IERC20 public immutable BRING_TOKEN;

    constructor(uint256 fee_, address feeRecipient_, IERC20 bringToken_) {
        fee = fee_;
        feeRecipient = feeRecipient_;
        BRING_TOKEN = bringToken_;
    }

    /**
     * @notice Create a new ERC20 drop.
     * @return dropAddress The address of the newly created drop.
     */
    function createDropByScore(
        IBringRegistry registry_,
        uint256 scoreThreshold_,
        IERC20 token_,
        uint256 amount_,
        uint256 maxClaims_,
        uint256 expiration_,
        string memory metadataIpfsHash_
    ) public returns (address dropAddress) {
        uint256 totalDistribution = amount_ * maxClaims_;
        uint256 feeAmount = (totalDistribution * fee) / 10000;

        BringDropByScore drop = new BringDropByScore(
            scoreThreshold_,
            registry_,
            msg.sender,
            token_,
            amount_,
            maxClaims_,
            expiration_,
            metadataIpfsHash_,
            BRING_TOKEN
        );
        dropAddress = address(drop);
        _distributeDropToken(token_, dropAddress, totalDistribution, feeAmount);
        emit DropCreated(
            msg.sender,
            dropAddress,
            address(token_),
            amount_,
            maxClaims_,
            expiration_,
            metadataIpfsHash_
        );
    }

    function _distributeDropToken(
        IERC20 token_,
        address dropAddress_,
        uint256 totalDistribution_,
        uint256 feeAmount_
    ) private {
        // Transfer fee tokens to feeRecipient.
        require(
            token_.transferFrom(msg.sender, feeRecipient, feeAmount_),
            "Fee transfer failed"
        );

        // Transfer distribution tokens to the created drop contract.
        require(
            token_.transferFrom(msg.sender, dropAddress_, totalDistribution_),
            "Token transfer to drop failed"
        );
    }

    // ONLY OWNER //
    function updateFee(uint256 _fee) external onlyOwner {
        require(_fee <= 10000, "Invalid fee");
        fee = _fee;
        emit FeeUpdated(_fee);
    }

    function updateFeeRecipient(address _feeRecipient) external onlyOwner {
        require(_feeRecipient != address(0), "Invalid fee recipient");
        feeRecipient = _feeRecipient;
        emit FeeRecipientUpdated(_feeRecipient);
    }
}
