// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import {BringDropBase} from "../src/drop/BringDropBase.sol";
import {CredentialRegistry} from "../src/registry/CredentialRegistry.sol";
import {ICredentialRegistry} from "../src/registry/ICredentialRegistry.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {ISemaphoreVerifier} from "semaphore-protocol/interfaces/ISemaphoreVerifier.sol";
import {SemaphoreVerifier} from "semaphore-protocol/base/SemaphoreVerifier.sol";
import {Semaphore} from "semaphore-protocol/Semaphore.sol";
import {Token} from "../src/mock/Token.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";

// Concrete implementation of BringDropBase for testing
contract TestBringDrop is BringDropBase {
    constructor(
        ICredentialRegistry registry_,
        address creator_,
        IERC20 token_,
        uint256 amount_,
        uint256 maxClaims_,
        uint256 expiration_,
        string memory metadataIpfsHash_,
        IERC20 bringToken_
    ) BringDropBase(
        registry_,
        creator_,
        token_,
        amount_,
        maxClaims_,
        expiration_,
        metadataIpfsHash_,
        bringToken_
    ) {}
}

contract BringDropBaseTest is Test {
    TestBringDrop drop;
    CredentialRegistry registry;
    Token token;
    Token bringToken;
    
    address creator;
    address user;
    uint256 constant AMOUNT = 10 * 10**18;
    uint256 constant MAX_CLAIMS = 100;
    uint256 constant TOKEN_SUPPLY = 1000000 * 10**18;
    uint256 expiration;
    string constant METADATA_HASH = "QmTestHash";
    
    event BringStaked(address bringToken, uint256 amount, uint256 totalStaked);
    event Stopped();
    event MetadataUpdated(string metadataIpfsHash);

    function setUp() public {
        creator = makeAddr("creator");
        user = makeAddr("user");
        expiration = block.timestamp + 7 days;
        
        // Deploy tokens
        token = new Token("Test Token", "TEST", user, TOKEN_SUPPLY);
        bringToken = new Token("Bring Token", "BRING", user, TOKEN_SUPPLY);
        
        // Deploy Semaphore contracts
        SemaphoreVerifier semaphoreVerifier = new SemaphoreVerifier();
        Semaphore semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));
        
        // Deploy registry
        address tlsnVerifier = makeAddr("tlsn-verifier");
        registry = new CredentialRegistry(ISemaphore(address(semaphore)), tlsnVerifier);
        
        // Deploy drop
        drop = new TestBringDrop(
            ICredentialRegistry(address(registry)),
            creator,
            IERC20(address(token)),
            AMOUNT,
            MAX_CLAIMS,
            expiration,
            METADATA_HASH,
            IERC20(address(bringToken))
        );
        
        // Fund the drop with tokens
        vm.prank(user);
        token.transfer(address(drop), AMOUNT * MAX_CLAIMS);
    }

    function testConstructor() public {
        assertEq(address(drop.registry()), address(registry));
        assertEq(address(drop.token()), address(token));
        assertEq(drop.amount(), AMOUNT);
        assertEq(drop.maxClaims(), MAX_CLAIMS);
        assertEq(drop.expiration(), expiration);
        assertEq(drop.metadataIpfsHash(), METADATA_HASH);
        assertEq(address(drop.BRING_TOKEN()), address(bringToken));
        assertEq(drop.owner(), creator);
        assertEq(drop.claims(), 0);
        assertEq(drop.bringStaked(), 0);
        assertFalse(drop.stopped());
    }

    function testScope() public {
        uint256 expectedScope = uint256(keccak256(abi.encode(address(drop), 0)));
        assertEq(drop.scope(), expectedScope);
    }

    function testStake() public {
        uint256 stakeAmount = 100 * 10**18;
        
        // Transfer tokens to creator first
        vm.prank(user);
        bringToken.transfer(creator, stakeAmount);
        
        // Approve and stake
        vm.startPrank(creator);
        bringToken.approve(address(drop), stakeAmount);
        
        vm.expectEmit(true, false, false, true);
        emit BringStaked(address(bringToken), stakeAmount, stakeAmount);
        
        drop.stake(stakeAmount);
        vm.stopPrank();
        
        assertEq(drop.bringStaked(), stakeAmount);
        assertEq(bringToken.balanceOf(address(drop)), stakeAmount);
    }

    function testStakeMultiple() public {
        uint256 stakeAmount1 = 100 * 10**18;
        uint256 stakeAmount2 = 50 * 10**18;
        
        // Transfer tokens to creator first
        vm.prank(user);
        bringToken.transfer(creator, stakeAmount1 + stakeAmount2);
        
        // First stake
        vm.startPrank(creator);
        
        bringToken.approve(address(drop), stakeAmount1);
        drop.stake(stakeAmount1);
        
        // Second stake
        bringToken.approve(address(drop), stakeAmount2);
        
        vm.expectEmit(true, false, false, true);
        emit BringStaked(address(bringToken), stakeAmount2, stakeAmount1 + stakeAmount2);
        
        drop.stake(stakeAmount2);
        vm.stopPrank();
        
        assertEq(drop.bringStaked(), stakeAmount1 + stakeAmount2);
        assertEq(bringToken.balanceOf(address(drop)), stakeAmount1 + stakeAmount2);
    }

    function testStakeOnlyOwner() public {
        uint256 stakeAmount = 100 * 10**18;
        
        vm.prank(user);
        bringToken.approve(address(drop), stakeAmount);
        
        vm.prank(user);
        vm.expectRevert("Ownable: caller is not the owner");
        drop.stake(stakeAmount);
    }

    function testStakeZeroAmount() public {
        vm.prank(creator);
        vm.expectRevert("Stake amount must be greater than zero");
        drop.stake(0);
    }

    function testStakeWhenStopped() public {
        uint256 stakeAmount = 100 * 10**18;
        
        // Stop the drop first
        vm.prank(creator);
        drop.stop();
        
        // Transfer tokens to creator first
        vm.prank(user);
        bringToken.transfer(creator, stakeAmount);
        
        vm.startPrank(creator);
        bringToken.approve(address(drop), stakeAmount);
        
        vm.expectRevert("Campaign stopped");
        drop.stake(stakeAmount);
        vm.stopPrank();
    }

    function testStakeWhenExpired() public {
        uint256 stakeAmount = 100 * 10**18;
        
        // Fast forward past expiration
        vm.warp(expiration + 1);
        
        // Transfer tokens to creator first
        vm.prank(user);
        bringToken.transfer(creator, stakeAmount);
        
        vm.startPrank(creator);
        bringToken.approve(address(drop), stakeAmount);
        
        vm.expectRevert("Drop has expired");
        drop.stake(stakeAmount);
        vm.stopPrank();
    }

    function testStakeInsufficientTokens() public {
        uint256 stakeAmount = 100 * 10**18;
        
        vm.startPrank(creator);
        bringToken.approve(address(drop), stakeAmount);
        
        vm.expectRevert("ERC20: transfer amount exceeds balance");
        drop.stake(stakeAmount);
        vm.stopPrank();
    }

    function testStop() public {
        uint256 stakeAmount = 100 * 10**18;
        
        // Transfer tokens to creator first
        vm.prank(user);
        bringToken.transfer(creator, stakeAmount);
        
        // Stake some tokens first
        vm.startPrank(creator);
        bringToken.approve(address(drop), stakeAmount);
        drop.stake(stakeAmount);
        
        uint256 initialTokenBalance = token.balanceOf(address(drop));
        uint256 initialBringBalance = bringToken.balanceOf(address(drop));
        
        vm.expectEmit(false, false, false, false);
        emit Stopped();
        
        drop.stop();
        vm.stopPrank();
        
        assertTrue(drop.stopped());
        assertEq(token.balanceOf(creator), initialTokenBalance);
        assertEq(bringToken.balanceOf(creator), initialBringBalance);
        assertEq(token.balanceOf(address(drop)), 0);
        assertEq(bringToken.balanceOf(address(drop)), 0);
        assertEq(drop.bringStaked(), 0);
    }

    function testStopWithoutStake() public {
        uint256 initialTokenBalance = token.balanceOf(address(drop));
        
        vm.expectEmit(false, false, false, false);
        emit Stopped();
        
        vm.prank(creator);
        drop.stop();
        
        assertTrue(drop.stopped());
        assertEq(token.balanceOf(creator), initialTokenBalance);
        assertEq(token.balanceOf(address(drop)), 0);
        assertEq(drop.bringStaked(), 0);
    }

    function testStopOnlyOwner() public {
        vm.prank(user);
        vm.expectRevert("Ownable: caller is not the owner");
        drop.stop();
    }

    function testStopAlreadyStopped() public {
        vm.prank(creator);
        drop.stop();
        
        vm.prank(creator);
        vm.expectRevert("Campaign stopped");
        drop.stop();
    }

    function testUpdateMetadata() public {
        string memory newMetadata = "QmNewTestHash";
        
        vm.expectEmit(false, false, false, true);
        emit MetadataUpdated(newMetadata);
        
        vm.prank(creator);
        drop.updateMetadata(newMetadata);
        
        assertEq(drop.metadataIpfsHash(), newMetadata);
    }

    function testUpdateMetadataOnlyOwner() public {
        vm.prank(user);
        vm.expectRevert("Ownable: caller is not the owner");
        drop.updateMetadata("QmNewTestHash");
    }

    function testUpdateMetadataWhenStopped() public {
        vm.prank(creator);
        drop.stop();
        
        vm.prank(creator);
        vm.expectRevert("Campaign stopped");
        drop.updateMetadata("QmNewTestHash");
    }

    function testUpdateMetadataWhenExpired() public {
        vm.warp(expiration + 1);
        
        vm.prank(creator);
        vm.expectRevert("Drop has expired");
        drop.updateMetadata("QmNewTestHash");
    }

    function testFuzzStake(uint256 stakeAmount) public {
        vm.assume(stakeAmount > 0 && stakeAmount <= TOKEN_SUPPLY);
        
        // Transfer tokens to creator first
        vm.prank(user);
        bringToken.transfer(creator, stakeAmount);
        
        vm.startPrank(creator);
        bringToken.approve(address(drop), stakeAmount);
        drop.stake(stakeAmount);
        vm.stopPrank();
        
        assertEq(drop.bringStaked(), stakeAmount);
        assertEq(bringToken.balanceOf(address(drop)), stakeAmount);
    }

    function testFuzzUpdateMetadata(string memory newMetadata) public {
        vm.assume(bytes(newMetadata).length > 0);
        
        vm.prank(creator);
        drop.updateMetadata(newMetadata);
        
        assertEq(drop.metadataIpfsHash(), newMetadata);
    }

    function testModifiersNotStopped() public {
        // Test that functions with notStopped modifier work before stopping
        vm.prank(creator);
        drop.updateMetadata("QmNewHash");
        
        // Stop the drop
        vm.prank(creator);
        drop.stop();
        
        // Test that functions with notStopped modifier fail after stopping
        vm.prank(creator);
        vm.expectRevert("Campaign stopped");
        drop.updateMetadata("QmAnotherHash");
    }

    function testModifiersNotExpired() public {
        // Test that functions with notExpired modifier work before expiration
        vm.prank(creator);
        drop.updateMetadata("QmNewHash");
        
        // Fast forward past expiration
        vm.warp(expiration + 1);
        
        // Test that functions with notExpired modifier fail after expiration
        vm.prank(creator);
        vm.expectRevert("Drop has expired");
        drop.updateMetadata("QmAnotherHash");
    }

    function testComplexScenario() public {
        // Test a complex scenario with multiple stakes and metadata updates
        uint256 stakeAmount1 = 100 * 10**18;
        uint256 stakeAmount2 = 50 * 10**18;
        
        // Transfer tokens to creator first
        vm.prank(user);
        bringToken.transfer(creator, stakeAmount1 + stakeAmount2);
        
        vm.startPrank(creator);
        
        // First stake
        bringToken.approve(address(drop), stakeAmount1);
        drop.stake(stakeAmount1);
        assertEq(drop.bringStaked(), stakeAmount1);
        
        // Update metadata
        drop.updateMetadata("QmNewHash1");
        assertEq(drop.metadataIpfsHash(), "QmNewHash1");
        
        // Second stake
        bringToken.approve(address(drop), stakeAmount2);
        drop.stake(stakeAmount2);
        assertEq(drop.bringStaked(), stakeAmount1 + stakeAmount2);
        
        // Update metadata again
        drop.updateMetadata("QmNewHash2");
        assertEq(drop.metadataIpfsHash(), "QmNewHash2");
        
        // Stop the drop
        drop.stop();
        
        // Verify all tokens were returned
        assertEq(token.balanceOf(creator), AMOUNT * MAX_CLAIMS);
        assertEq(bringToken.balanceOf(creator), stakeAmount1 + stakeAmount2);
        assertEq(drop.bringStaked(), 0);
        assertTrue(drop.stopped());
        vm.stopPrank();
    }
}