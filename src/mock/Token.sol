// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;
import {ERC20} from "openzeppelin/token/ERC20/ERC20.sol";

contract Token is ERC20 {
    constructor(
        string memory name_,
        string memory symbol_,
        address mintTo,
        uint256 mintAmount
    ) ERC20(name_, symbol_){
        _mint(mintTo, mintAmount);
    }
}
