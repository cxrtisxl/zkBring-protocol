import { ethers } from "ethers";
import { Identity, generateProof, Group } from "@semaphore-protocol/core";

const privateKey = process.argv[2];
const scope = process.argv[3];

if (process.argv.length < 5) {
    console.log("Usage: node proof.js <privateKey> <scope> <groupCommitments...>");
    process.exit(1);
}

const identity = Identity.import(privateKey);
const group = new Group();
for (let i = 4; i < process.argv.length; i++) {
    group.addMember(process.argv[i]);
}

const {
    merkleTreeDepth, merkleTreeRoot, nullifier, message, points
} = await generateProof(
    identity, group, "verification", scope
);

console.log(
    (new ethers.AbiCoder).encode(
        ["uint256", "uint256", "uint256", "uint256", "uint256[8]"],
        [merkleTreeDepth, merkleTreeRoot, nullifier, message, points]
    )
);
process.exit(0);