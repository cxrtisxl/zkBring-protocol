// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

// BringDropFactory events
event DropCreated(
    address indexed creator,
    address indexed drop,
    address indexed token,
    uint256 amount,
    uint256 maxClaims,
    uint256 expiration,
    string metadataIpfsHash
);

event FeeUpdated(uint256 newFee);
event FeeRecipientUpdated(address newFeeRecipient);

// BringDrop events
event MetadataUpdated(string metadataIpfsHash);
event BringStaked(address bringToken, uint256 amount, uint256 totalStaked);
event zkPassSchemaIdUpdated(bytes32 zkPassSchemaId);
event Stopped();