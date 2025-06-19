import { ethers } from "ethers";
import { Identity } from "@semaphore-protocol/core";

const privateKey = process.argv[2];

console.log(
    (new ethers.AbiCoder).encode(
        ["uint256"],
        [Identity.import(privateKey).commitment]
    )
);
