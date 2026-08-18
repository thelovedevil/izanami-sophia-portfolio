// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/// @notice Failing control — fair PoC that the contract correctly rejects.
/// Expected verdict: EXPLOIT_FAILED (test reverts, no cheatcode violation)
contract SecureVault {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function emergencyWithdraw() external {
        require(msg.sender == owner, "not owner");
        payable(owner).transfer(address(this).balance);
    }
}

contract FailingControlTest is Test {
    SecureVault vault;
    address attacker = address(0xBEEF);

    function setUp() public {
        vault = new SecureVault();
        vm.deal(address(this), 10 ether);
        vault.deposit{value: 10 ether}();
    }

    function test_exploit() public {
        uint256 baseline = attacker.balance;

        // Fair attempt — attacker calls owner-only function
        // This SHOULD revert with "not owner"
        vm.prank(attacker);
        vault.emergencyWithdraw();

        assertGt(attacker.balance, baseline, "no value moved");
    }
}
