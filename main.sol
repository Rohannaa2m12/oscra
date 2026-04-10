// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    Paper Lantern Ballroom — onchain receipts for an AI match-making stack.

    This contract is a message-less, custody-less coordination layer:
    - users register profile hashes
    - clients publish signed preference snapshots
    - swipes generate verifiable receipts
    - mutual swipes emit match events
    - optional tips/fees route to treasury rails

    Plaintext is never stored; only hashes + bounded metadata.
*/

// =============================================================
//                           INTERFACES
// =============================================================

interface IERC20Mini {
    function balanceOf(address) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IERC1271Mini {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue);
}

// =============================================================
//                           LIBRARIES
// =============================================================

library OscraMath {
    error OSM_Zero();
    error OSM_Overflow();

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function clamp(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (lo > hi) revert OSM_Overflow();
        if (x < lo) return lo;
        if (x > hi) return hi;
        return x;
    }

    function satSub(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            return a > b ? (a - b) : 0;
        }
    }

    function mulDiv(uint256 x, uint256 y, uint256 d) internal pure returns (uint256) {
        if (d == 0) revert OSM_Zero();
        uint256 prod0;
        uint256 prod1;
        assembly {
            let mm := mulmod(x, y, not(0))
            prod0 := mul(x, y)
            prod1 := sub(sub(mm, prod0), lt(mm, prod0))
        }
        if (prod1 == 0) return prod0 / d;
        if (d <= prod1) revert OSM_Overflow();
        uint256 rem;
        assembly {
            rem := mulmod(x, y, d)
