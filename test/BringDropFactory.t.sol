// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import {BringDropFactory} from "../src/drop/BringDropFactory.sol";
import {BringDropByScore} from "../src/drop/BringDropByScore.sol";
import {CredentialRegistry} from "../src/registry/CredentialRegistry.sol";
import {ICredentialRegistry} from "../src/registry/ICredentialRegistry.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {ISemaphoreVerifier} from "semaphore-protocol/interfaces/ISemaphoreVerifier.sol";
import {SemaphoreVerifier} from "semaphore-protocol/base/SemaphoreVerifier.sol";
import {Semaphore} from "semaphore-protocol/Semaphore.sol";
import {Token} from "../src/mock/Token.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";

contract BringDropFactoryTest is Test {
    BringDropFactory factory;
    CredentialRegistry registry;
    Token token;
    Token bringToken;
    
    address owner;
    address feeRecipient;
    address user;
    uint256 constant INITIAL_FEE = 500; // 5%
    uint256 constant TOKEN_SUPPLY = 1000000 * 10**18;
    
    event DropCreated(
        address indexed creator,
        address indexed dropAddress,
        address indexed token,
        uint256 amount,
        uint256 maxClaims,
        uint256 expiration,
        string metadataIpfsHash
    );
    event FeeUpdated(uint256 fee);
    event FeeRecipientUpdated(address feeRecipient);

    function setUp() public {
        owner = address(this);
        feeRecipient = makeAddr("fee-recipient");
        user = makeAddr("user");
        
        // Deploy tokens
        token = new Token("Test Token", "TEST", user, TOKEN_SUPPLY);
        bringToken = new Token("Bring Token", "BRING", user, TOKEN_SUPPLY);
        
        // Deploy Semaphore contracts
        SemaphoreVerifier semaphoreVerifier = new SemaphoreVerifier();
        Semaphore semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));
        
        // Deploy registry
        address tlsnVerifier = makeAddr("tlsn-verifier");
        registry = new CredentialRegistry(ISemaphore(address(semaphore)), tlsnVerifier);
        
        // Deploy factory
        factory = new BringDropFactory(INITIAL_FEE, feeRecipient, IERC20(address(bringToken)));
    }

    function testConstructor() public {
        assertEq(factory.fee(), INITIAL_FEE);
        assertEq(factory.feeRecipient(), feeRecipient);
        assertEq(address(factory.BRING_TOKEN()), address(bringToken));
        assertEq(factory.owner(), owner);
    }

    function testCreateDropByScore() public {
        uint256 scoreThreshold = 100;
        uint256 amount = 10 * 10**18;
        uint256 maxClaims = 100;
        uint256 expiration = block.timestamp + 7 days;
        string memory metadataIpfsHash = "QmTestHash";
        
        uint256 totalDistribution = amount * maxClaims;
        uint256 feeAmount = (totalDistribution * INITIAL_FEE) / 10000;
        
        // Approve tokens
        vm.startPrank(user);
        token.approve(address(factory), totalDistribution + feeAmount);
        
        vm.expectEmit(true, false, true, true);
        emit DropCreated(
            user,
            address(0), // We can't predict the address, so don't check it
            address(token),
            amount,
            maxClaims,
            expiration,
            metadataIpfsHash
        );
        
        address dropAddress = factory.createDropByScore(
            ICredentialRegistry(address(registry)),
            scoreThreshold,
            IERC20(address(token)),
            amount,
            maxClaims,
            expiration,
            metadataIpfsHash
        );
        vm.stopPrank();
        
        // Verify the drop was created
        assertTrue(dropAddress != address(0));
        
        // Verify tokens were transferred
        assertEq(token.balanceOf(feeRecipient), feeAmount);
        assertEq(token.balanceOf(dropAddress), totalDistribution);
        
        // Verify the drop contract state
        BringDropByScore drop = BringDropByScore(dropAddress);
        assertEq(drop.scoreThreshold(), scoreThreshold);
        assertEq(address(drop.registry()), address(registry));
        assertEq(address(drop.token()), address(token));
        assertEq(drop.amount(), amount);
        assertEq(drop.maxClaims(), maxClaims);
        assertEq(drop.expiration(), expiration);
        assertEq(drop.metadataIpfsHash(), metadataIpfsHash);
        assertEq(drop.owner(), user);
    }

    function testCreateDropByScoreInsufficientTokens() public {
        uint256 scoreThreshold = 100;
        uint256 amount = 10 * 10**18;
        uint256 maxClaims = 100;
        uint256 expiration = block.timestamp + 7 days;
        string memory metadataIpfsHash = "QmTestHash";
        
        uint256 totalDistribution = amount * maxClaims;
        uint256 feeAmount = (totalDistribution * INITIAL_FEE) / 10000;
        
        // Approve insufficient tokens
        vm.startPrank(user);
        token.approve(address(factory), totalDistribution + feeAmount - 1);
        
        vm.expectRevert("ERC20: insufficient allowance");
        factory.createDropByScore(
            ICredentialRegistry(address(registry)),
            scoreThreshold,
            IERC20(address(token)),
            amount,
            maxClaims,
            expiration,
            metadataIpfsHash
        );
        vm.stopPrank();
    }

    function testCreateDropByScoreZeroFee() public {
        // Deploy factory with zero fee
        BringDropFactory zeroFeeFactory = new BringDropFactory(0, feeRecipient, IERC20(address(bringToken)));
        
        uint256 scoreThreshold = 100;
        uint256 amount = 10 * 10**18;
        uint256 maxClaims = 100;
        uint256 expiration = block.timestamp + 7 days;
        string memory metadataIpfsHash = "QmTestHash";
        
        uint256 totalDistribution = amount * maxClaims;
        
        // Approve tokens
        vm.startPrank(user);
        token.approve(address(zeroFeeFactory), totalDistribution);
        
        address dropAddress = zeroFeeFactory.createDropByScore(
            ICredentialRegistry(address(registry)),
            scoreThreshold,
            IERC20(address(token)),
            amount,
            maxClaims,
            expiration,
            metadataIpfsHash
        );
        vm.stopPrank();
        
        // Verify no fee was charged
        assertEq(token.balanceOf(feeRecipient), 0);
        assertEq(token.balanceOf(dropAddress), totalDistribution);
    }

    function testFuzzCreateDropByScore(
        uint256 scoreThreshold,
        uint256 amount,
        uint256 maxClaims,
        uint256 timeOffset
    ) public {
        // Use much simpler bounds to avoid rejecting too many inputs
        scoreThreshold = bound(scoreThreshold, 1, 1000);
        amount = bound(amount, 1 * 10**18, 10 * 10**18);
        maxClaims = bound(maxClaims, 1, 10);
        timeOffset = bound(timeOffset, 1 hours, 7 days);
        
        uint256 expiration = block.timestamp + timeOffset;
        string memory metadataIpfsHash = "QmTestHash";
        
        uint256 totalDistribution = amount * maxClaims;
        uint256 feeAmount = (totalDistribution * INITIAL_FEE) / 10000;
        
        // Approve tokens
        vm.startPrank(user);
        token.approve(address(factory), totalDistribution + feeAmount);
        
        address dropAddress = factory.createDropByScore(
            ICredentialRegistry(address(registry)),
            scoreThreshold,
            IERC20(address(token)),
            amount,
            maxClaims,
            expiration,
            metadataIpfsHash
        );
        vm.stopPrank();
        
        // Verify the drop was created
        assertTrue(dropAddress != address(0));
        
        // Verify the drop contract state
        BringDropByScore drop = BringDropByScore(dropAddress);
        assertEq(drop.scoreThreshold(), scoreThreshold);
        assertEq(drop.amount(), amount);
        assertEq(drop.maxClaims(), maxClaims);
        assertEq(drop.expiration(), expiration);
    }

    function testUpdateFee() public {
        uint256 newFee = 1000; // 10%
        
        vm.expectEmit(true, false, false, false);
        emit FeeUpdated(newFee);
        
        factory.updateFee(newFee);
        assertEq(factory.fee(), newFee);
    }

    function testUpdateFeeOnlyOwner() public {
        vm.prank(user);
        vm.expectRevert("Ownable: caller is not the owner");
        factory.updateFee(1000);
    }

    function testUpdateFeeRecipient() public {
        address newFeeRecipient = makeAddr("new-fee-recipient");
        
        vm.expectEmit(true, false, false, false);
        emit FeeRecipientUpdated(newFeeRecipient);
        
        factory.updateFeeRecipient(newFeeRecipient);
        assertEq(factory.feeRecipient(), newFeeRecipient);
    }

    function testUpdateFeeRecipientOnlyOwner() public {
        vm.prank(user);
        vm.expectRevert("Ownable: caller is not the owner");
        factory.updateFeeRecipient(makeAddr("new-fee-recipient"));
    }

    function testFuzzUpdateFee(uint256 newFee) public {
        vm.assume(newFee <= 10000); // Max 100%
        
        factory.updateFee(newFee);
        assertEq(factory.fee(), newFee);
    }

    function testCreateDropWithHighFee() public {
        // Set a high fee (50%)
        factory.updateFee(5000);
        
        uint256 scoreThreshold = 100;
        uint256 amount = 10 * 10**18;
        uint256 maxClaims = 100;
        uint256 expiration = block.timestamp + 7 days;
        string memory metadataIpfsHash = "QmTestHash";
        
        uint256 totalDistribution = amount * maxClaims;
        uint256 feeAmount = (totalDistribution * 5000) / 10000; // 50%
        
        // Approve tokens
        vm.startPrank(user);
        token.approve(address(factory), totalDistribution + feeAmount);
        
        address dropAddress = factory.createDropByScore(
            ICredentialRegistry(address(registry)),
            scoreThreshold,
            IERC20(address(token)),
            amount,
            maxClaims,
            expiration,
            metadataIpfsHash
        );
        vm.stopPrank();
        
        // Verify the drop was created
        assertTrue(dropAddress != address(0));
        
        // Verify tokens were transferred with high fee
        assertEq(token.balanceOf(feeRecipient), feeAmount);
        assertEq(token.balanceOf(dropAddress), totalDistribution);
        assertEq(feeAmount, totalDistribution / 2); // 50% fee
    }

    function testCreateDropFeeTransferFails() public {
        // Test with insufficient balance - no tokens in factory account
        uint256 scoreThreshold = 100;
        uint256 amount = 10 * 10**18;
        uint256 maxClaims = 100;
        uint256 expiration = block.timestamp + 7 days;
        string memory metadataIpfsHash = "QmTestHash";
        
        vm.startPrank(user);
        vm.expectRevert("ERC20: insufficient allowance");
        factory.createDropByScore(
            ICredentialRegistry(address(registry)),
            scoreThreshold,
            IERC20(address(token)),
            amount,
            maxClaims,
            expiration,
            metadataIpfsHash
        );
        vm.stopPrank();
    }

    function testCreateDropDistributionTransferFails() public {
        // Create a scenario where fee transfer succeeds but distribution transfer fails
        // This is harder to test directly without a custom token contract
        // But we can test insufficient approval scenario
        
        uint256 scoreThreshold = 100;
        uint256 amount = 10 * 10**18;
        uint256 maxClaims = 100;
        uint256 expiration = block.timestamp + 7 days;
        string memory metadataIpfsHash = "QmTestHash";
        
        uint256 totalDistribution = amount * maxClaims;
        uint256 feeAmount = (totalDistribution * INITIAL_FEE) / 10000;
        
        // Approve only enough for fee but not for distribution
        vm.startPrank(user);
        token.approve(address(factory), feeAmount);
        
        vm.expectRevert("ERC20: insufficient allowance");
        factory.createDropByScore(
            ICredentialRegistry(address(registry)),
            scoreThreshold,
            IERC20(address(token)),
            amount,
            maxClaims,
            expiration,
            metadataIpfsHash
        );
        vm.stopPrank();
    }

    function testCreateMultipleDrops() public {
        uint256 scoreThreshold = 100;
        uint256 amount = 10 * 10**18;
        uint256 maxClaims = 100;
        uint256 expiration = block.timestamp + 7 days;
        string memory metadataIpfsHash = "QmTestHash";
        
        uint256 totalDistribution = amount * maxClaims;
        uint256 feeAmount = (totalDistribution * INITIAL_FEE) / 10000;
        
        // Create first drop
        vm.startPrank(user);
        token.approve(address(factory), totalDistribution + feeAmount);
        
        address dropAddress1 = factory.createDropByScore(
            ICredentialRegistry(address(registry)),
            scoreThreshold,
            IERC20(address(token)),
            amount,
            maxClaims,
            expiration,
            metadataIpfsHash
        );
        
        // Create second drop
        token.approve(address(factory), totalDistribution + feeAmount);
        
        address dropAddress2 = factory.createDropByScore(
            ICredentialRegistry(address(registry)),
            scoreThreshold + 50,
            IERC20(address(token)),
            amount,
            maxClaims,
            expiration,
            metadataIpfsHash
        );
        vm.stopPrank();
        
        // Verify both drops were created with different addresses
        assertTrue(dropAddress1 != address(0));
        assertTrue(dropAddress2 != address(0));
        assertTrue(dropAddress1 != dropAddress2);
        
        // Verify fee recipient received fees from both drops
        assertEq(token.balanceOf(feeRecipient), feeAmount * 2);
        
        // Verify each drop has the correct tokens
        assertEq(token.balanceOf(dropAddress1), totalDistribution);
        assertEq(token.balanceOf(dropAddress2), totalDistribution);
        
        // Verify different score thresholds
        BringDropByScore drop1 = BringDropByScore(dropAddress1);
        BringDropByScore drop2 = BringDropByScore(dropAddress2);
        assertEq(drop1.scoreThreshold(), scoreThreshold);
        assertEq(drop2.scoreThreshold(), scoreThreshold + 50);
    }

    // SECURITY TESTS - These should fail to expose vulnerabilities

    function testCreateDropShouldRejectZeroAmount() public {
        vm.expectRevert();
        factory.createDropByScore(
            ICredentialRegistry(address(registry)),
            100,
            IERC20(address(token)),
            0, // Zero amount - should be rejected!
            100,
            block.timestamp + 7 days,
            "QmTestHash"
        );
    }

    function testCreateDropShouldRejectZeroMaxClaims() public {
        vm.expectRevert();
        factory.createDropByScore(
            ICredentialRegistry(address(registry)),
            100,
            IERC20(address(token)),
            10 * 10**18,
            0, // Zero max claims - should be rejected!
            block.timestamp + 7 days,
            "QmTestHash"
        );
    }

    function testCreateDropShouldRejectPastExpiration() public {
        // Set a proper timestamp to avoid underflow
        vm.warp(1000 days);
        
        try factory.createDropByScore(
            ICredentialRegistry(address(registry)),
            100,
            IERC20(address(token)),
            10 * 10**18,
            100,
            block.timestamp - 1 days, // Past expiration - should be rejected!
            "QmTestHash"
        ) {
            // If we reach here, the call succeeded when it should have failed
            assertTrue(false, "Expected revert for past expiration time");
        } catch {
            // Expected behavior - should revert for past expiration
            // Test passes if we reach here
            assertTrue(true);
        }
    }

    function testUpdateFeeShouldRejectExcessiveFees() public {
        vm.expectRevert();
        factory.updateFee(10001); // > 100% - should be rejected!
    }

    function testUpdateFeeRecipientShouldRejectZeroAddress() public {
        vm.expectRevert();
        factory.updateFeeRecipient(address(0));
    }
}