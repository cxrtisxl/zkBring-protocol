import { ethers } from "ethers";
import { Identity } from "@semaphore-protocol/core";

const privateKey = process.argv0;

const identity = Identity.import(privateKey);
const commitment = identity.commitment.toString();

const abiCoder = new ethers.AbiCoder;
console.log(commitment);

// console.log(abiCoder.encode(["string"], ["Hello FFI"]))