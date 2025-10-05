// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "../registry/ICredentialRegistry.sol";
import {ERC721} from "solmate/tokens/ERC721.sol";
import {Ownable2Step} from "openzeppelin/access/Ownable2Step.sol";
import {Strings} from "openzeppelin/utils/Strings.sol";
import {Base64} from "openzeppelin/utils/Base64.sol";
import {Pausable} from "openzeppelin/security/Pausable.sol";

contract IdCard is ERC721, Ownable2Step {
    using Strings for uint256;

    struct ID {
        uint256 score;
        uint256[] verifications;
    }

    mapping (uint256 registryGroupId => string name) private _names;
    mapping (address extId => uint256 id) private _toLocalId;
    uint256 private _lastId;

    ICredentialRegistry public immutable registry;
    mapping (uint256 id => ID) public IDs;
    bool public stopped;

    modifier notStopped() {
        require(!stopped, "Campaign stopped");
        _;
    }

    constructor(ICredentialRegistry registry_) ERC721("Bring ID Card", "Bring ID") {
        registry = registry_;
        _names[1] = "X account owner";
        _names[2] = "Has Uber rides";
    }

    function minted(address id) public view returns (bool) {
        return _toLocalId[id] != 0;
    }

    function tokenURI(address id) public view returns (string memory metadata) {
        return tokenURI(_toLocalId[id]);
    }

    function tokenURI(uint256 id) public view override returns (string memory metadata) {
        require(id != 0 && id <= _lastId, "ID doesn't exist");
        ID memory id_ = IDs[id];
        metadata = string(abi.encodePacked(
            "{\"name\": \"Bring ID Card #", id.toString(), "\",",
            "\"image\": \"https://www.bringid.org/", id_.score.toString(), "\",",
            "\"external_url\": \"https://www.bringid.org/\","
            "\"description\": \"Bring ID is...\","
            "\"attributes\": ["
        ));

        for (uint256 i = 0; i < id_.verifications.length-1; i++) {
            metadata = string(abi.encodePacked(
                metadata,
                "{\"trait_type\": \"Verification\",",
                "\"value\": \"", _names[id_.verifications[i]] ,"\"},"
            ));
        }
        metadata = string(abi.encodePacked(
            metadata,
            "{\"trait_type\": \"Verification\",",
            "\"value\": \"", _names[id_.verifications[id_.verifications.length-1]] ,"\"}]}"
        ));

        return string.concat("data:application/json;base64,", Base64.encode(bytes(metadata)));
    }

    function claim(
        address to,
        ICredentialRegistry.CredentialGroupProof[] calldata proofs
    ) public notStopped {
        uint256 id = _toLocalId[to];
        bool shouldMint = (id == 0);
        for (uint256 i; i < proofs.length; i++) {
            registry.validateProof(0, proofs[i]);
            uint256 score = registry.credentialGroupScore(proofs[i].credentialGroupId);
            if (id == 0) {
                id = _nextId(to);
                uint256[] memory verifications_ = new uint256[](1);
                verifications_[0] = proofs[i].credentialGroupId;
                IDs[id] = ID(score, verifications_);
            } else {
                IDs[id].score += score;
                IDs[id].verifications.push(proofs[i].credentialGroupId);
            }
        }
        if (shouldMint) _mint(to, id);
    }

    function toggleStop() public onlyOwner {
        stopped = !stopped;
    }

    function _nextId(address extId) private returns (uint256 id) {
        id = ++_lastId;
        _toLocalId[extId] = id;
    }
}
