// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IBringRegistry} from "./IBringRegistry.sol";

event VerificationCreated(uint256 indexed verificationId, IBringRegistry.Verification verification);
event Verified(uint256 indexed verificationId, uint256 indexed commitment);
event Proved(uint256 indexed verificationId);

event TLSNVerifierSet(address indexed verifier);

