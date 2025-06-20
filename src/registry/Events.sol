// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

event VerificationCreated(uint256 verificationId);
event Verified(uint256 indexed verificationId, uint256 indexed commitment);
event Proved(uint256 indexed verificationId);

event TLSNVerifierSet(address indexed verifier);

