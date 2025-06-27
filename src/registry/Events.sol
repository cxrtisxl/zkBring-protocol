// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IzkBringRegistry} from "./IzkBringRegistry.sol";

event VerificationCreated(uint256 indexed verificationId, IzkBringRegistry.Verification verification);
event Verified(uint256 indexed verificationId, uint256 indexed commitment);
event Proved(uint256 indexed verificationId);

event TLSNVerifierSet(address indexed verifier);

