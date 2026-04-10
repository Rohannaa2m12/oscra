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
            prod1 := sub(prod1, gt(rem, prod0))
            prod0 := sub(prod0, rem)
        }
        uint256 twos = d & (~d + 1);
        assembly {
            d := div(d, twos)
            prod0 := div(prod0, twos)
            twos := add(div(sub(0, twos), twos), 1)
        }
        prod0 |= prod1 * twos;
        uint256 inv = (3 * d) ^ 2;
        unchecked {
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
        }
        return prod0 * inv;
    }
}

library OscraAddr {
    error OSA_CallFailed();
    error OSA_BadReturn();
    error OSA_NotContract();

    function isContract(address a) internal view returns (bool) {
        return a.code.length != 0;
    }

    function safeTransferETH(address to, uint256 amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert OSA_CallFailed();
    }

    function safeTransfer(IERC20Mini t, address to, uint256 amount) internal {
        bytes memory data = abi.encodeWithSelector(t.transfer.selector, to, amount);
        bytes memory ret = _call(address(t), data);
        if (ret.length != 0 && !abi.decode(ret, (bool))) revert OSA_BadReturn();
    }

    function safeTransferFrom(IERC20Mini t, address from, address to, uint256 amount) internal {
        bytes memory data = abi.encodeWithSelector(t.transferFrom.selector, from, to, amount);
        bytes memory ret = _call(address(t), data);
        if (ret.length != 0 && !abi.decode(ret, (bool))) revert OSA_BadReturn();
    }

    function _call(address target, bytes memory data) private returns (bytes memory) {
        if (!isContract(target)) revert OSA_NotContract();
        (bool ok, bytes memory out) = target.call(data);
        if (!ok) revert OSA_CallFailed();
        return out;
    }
}

library OscraSig {
    error OSS_BadSigLen();
    error OSS_BadS();
    error OSS_BadV();

    uint256 internal constant _HALF_N =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    function recover(bytes32 digest, bytes calldata sig) internal pure returns (address signer) {
        if (sig.length != 65) revert OSS_BadSigLen();
        bytes32 r;
        bytes32 s;
