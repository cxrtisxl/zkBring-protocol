// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IBringRegistry} from "../registry/IBringRegistry.sol";
import {Ownable2Step} from "openzeppelin/access/Ownable2Step.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import "./Events.sol";

abstract contract BringDropBase is Ownable2Step {
    // Drop configuration
    IBringRegistry public immutable registry;
    IERC20 public immutable token;
    uint256 public immutable amount; // Amount per claim
    uint256 public immutable maxClaims; // Maximum number of claims allowed
    uint256 public immutable expiration; // Expiration timestamp
    IERC20 public immutable BRING_TOKEN;

    uint256 public bringStaked;
    uint256 public claims; // Current number of claims
    string public metadataIpfsHash;
    bool public stopped;

    modifier notStopped() {
        require(!stopped, "Campaign stopped");
        _;
    }

    modifier notExpired() {
        require(block.timestamp < expiration, "Drop has expired");
        _;
    }

    /**
     * @notice Constructor sets the drop parameters and transfers ownership to the creator.
     */
    constructor(
        IBringRegistry registry_,
        address creator_,
        IERC20 token_,
        uint256 amount_,
        uint256 maxClaims_,
        uint256 expiration_,
        string memory metadataIpfsHash_,
        IERC20 bringToken_
    ) {
        require(amount_ > 0, "Amount must be greater than zero");
        require(maxClaims_ > 0, "Max claims must be greater than zero");
        require(expiration_ > block.timestamp, "Expiration must be in the future");
        registry = registry_;
        token = token_;
        amount = amount_;
        maxClaims = maxClaims_;
        expiration = expiration_;
        metadataIpfsHash = metadataIpfsHash_;
        BRING_TOKEN = bringToken_;

        // Set the owner to the drop creator.
        _transferOwnership(creator_);
    }

    function scope() public view virtual returns (uint256) {
        return uint256(keccak256(abi.encode(address(this), 0)));
    }

    /**
     * @notice Stake bring tokens. Can be called multiple times to add additional stake.
     */
    function stake(uint256 amount_) public onlyOwner notStopped notExpired {
        require(amount_ > 0, "Stake amount must be greater than zero");
        require(
            BRING_TOKEN.transferFrom(msg.sender, address(this), amount_),
            "Bring token transfer failed"
        );
        bringStaked += amount_;
        emit BringStaked(address(BRING_TOKEN), amount_, bringStaked);
    }

    /**
     * @notice Stop the drop campaign and return all tokens held by the contract to the owner.
     * Can only be called by the owner.
     */
    function stop() public onlyOwner notStopped {
        stopped = true;
        uint256 remaining = token.balanceOf(address(this));
        require(
            token.transfer(owner(), remaining),
            "Token transfer failed"
        );

        if (bringStaked > 0) {
            bringStaked = 0;
            uint256 bringBalance = BRING_TOKEN.balanceOf(address(this));
            require(
                BRING_TOKEN.transfer(owner(), bringBalance),
                "Bring token transfer failed"
            );
        }

        emit Stopped();
    }

    function updateMetadata(string memory _metadataIpfsHash) public onlyOwner notStopped notExpired {
        metadataIpfsHash = _metadataIpfsHash;
        emit MetadataUpdated(_metadataIpfsHash);
    }
}
