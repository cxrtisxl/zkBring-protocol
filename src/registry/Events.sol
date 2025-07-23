// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ICredentialRegistry} from "./ICredentialRegistry.sol";

event CredentialGroupCreated(uint256 indexed credentialGroupId, ICredentialRegistry.CredentialGroup credentialGroup);
event CredentialAdded(uint256 indexed credentialGroupId, uint256 indexed commitment);
event ProofValidated(uint256 indexed credentialGroupId);

event TLSNVerifierSet(address indexed verifier);

