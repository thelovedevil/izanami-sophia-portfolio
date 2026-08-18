// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/// @notice Negative control — fabricated exploit using vm.store.
/// Expected verdict: INVALID_PROOF (cheatcode violation)
contract SecureVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}

contract NegativeControlTest is Test {
    SecureVault vault;
    address attacker = address(0xBEEF);

    function setUp() public {
        vault = new SecureVault();
        vm.deal(address(vault), 10 ether);
    }

    function test_exploit() public {
        uint256 baseline = attacker.balance;

        // CHEAT: directly write fake balance via vm.store
        // This should be caught by Aletheia Layer 1
        bytes32 slot = keccak256(abi.encode(attacker, uint256(0)));
        vm.store(address(vault), slot, bytes32(uint256(10 ether)));

        vm.prank(attacker);
        vault.withdraw();

        assertGt(attacker.balance, baseline, "no value moved");
    }
}
