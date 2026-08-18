// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/// @notice Positive control — genuine exploit of unguarded drain().
/// Expected verdict: CONFIRMED
contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @dev VULNERABILITY: no access control, anyone can drain
    function drain() external {
        uint256 amount = address(this).balance;
        payable(msg.sender).transfer(amount);
    }
}

contract PositiveControlTest is Test {
    VulnerableVault vault;
    address attacker = address(0xBEEF);

    function setUp() public {
        vault = new VulnerableVault();
        // Legitimate deposit by victim
        vm.deal(address(this), 10 ether);
        vault.deposit{value: 10 ether}();
    }

    function test_exploit() public {
        uint256 baseline = attacker.balance;

        vm.prank(attacker);
        vault.drain();

        assertGt(attacker.balance, baseline, "no value moved");
    }
}
