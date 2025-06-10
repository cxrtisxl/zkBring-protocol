// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Ownable2Step} from "openzeppelin/access/Ownable2Step.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

contract TLSNValidator {
    using ECDSA for bytes32;

    struct VerifierMessage {
        address registry;
        uint256 verificationId;
        bytes32 idHash;
    }

    address public verifier;

    constructor(address verifier_) {
        verifier = verifier_;
    }


}
