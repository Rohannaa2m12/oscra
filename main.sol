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
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (uint256(s) > _HALF_N) revert OSS_BadS();
        if (v != 27 && v != 28) revert OSS_BadV();
        return ecrecover(digest, v, r, s);
    }
}

abstract contract OscraEIP712 {
    bytes32 private immutable _NAME_HASH;
    bytes32 private immutable _VER_HASH;
    bytes32 private immutable _DOMAIN_TYPEHASH;

    constructor(string memory name, string memory version) {
        _NAME_HASH = keccak256(bytes(name));
        _VER_HASH = keccak256(bytes(version));
        _DOMAIN_TYPEHASH = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(_DOMAIN_TYPEHASH, _NAME_HASH, _VER_HASH, block.chainid, address(this)));
    }

    function _hashTyped(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }
}

abstract contract OscraLock {
    error OSL_Reentered();
    uint256 private _g;
    modifier nonReentrant() {
        if (_g == 2) revert OSL_Reentered();
        _g = 2;
        _;
        _g = 1;
    }
}

// =============================================================
//                           MAIN CONTRACT
// =============================================================

contract oscra is OscraEIP712("oscra", "1.0.0"), OscraLock {
    using OscraAddr for IERC20Mini;
    using OscraMath for uint256;

    // -----------------------------
    // Errors (unique)
    // -----------------------------
    error OSC_Unauthorized();
    error OSC_Paused();
    error OSC_Zero();
    error OSC_Bounds();
    error OSC_Exists();
    error OSC_NotFound();
    error OSC_Expired();
    error OSC_BadSig();
    error OSC_Same();
    error OSC_Limit();
    error OSC_Fee();
    error OSC_TransferFailed();

    // -----------------------------
    // Events (unique)
    // -----------------------------
    event OSC_ProfileMinted(address indexed user, uint64 indexed profileId, bytes32 profileHash, bytes12 flair);
    event OSC_ProfileUpdated(address indexed user, uint64 indexed profileId, bytes32 newProfileHash);
    event OSC_PreferencesStamped(address indexed user, bytes32 prefsHash, uint64 nonce, uint64 stampedAt);
    event OSC_SwipeReceipt(address indexed from, address indexed to, uint8 kind, uint64 fromPid, uint64 toPid, bytes32 receipt);
    event OSC_MatchBond(address indexed a, address indexed b, uint64 matchId, bytes32 matchKey);
    event OSC_Unmatch(address indexed a, address indexed b, uint64 matchId, bytes32 reason);
    event OSC_GuardianShift(address indexed oldGuardian, address indexed newGuardian);
    event OSC_AdminShift(address indexed oldAdmin, address indexed newAdmin);
    event OSC_PauseToggled(bool paused);
    event OSC_FeeSchedule(uint16 swipeFeeBps, uint96 tipFloorWei, uint96 maxTipWei);
    event OSC_TipRouted(address indexed from, address indexed to, uint256 amount, uint256 fee);
    event OSC_TreasurySweep(address indexed to, uint256 amount);

    // -----------------------------
    // Immutable rails (random addresses)
    // -----------------------------
    address public immutable TREASURY_RAIL;
    address public immutable GUARD_RAIL;
    address public immutable SINK_RAIL;

    // -----------------------------
    // Admin / guardian / pause
    // -----------------------------
    address public admin;
    address public guardian;
    bool public paused;

    modifier onlyAdmin() {
        if (msg.sender != admin) revert OSC_Unauthorized();
        _;
    }

    modifier onlyGuardian() {
        if (msg.sender != guardian) revert OSC_Unauthorized();
        _;
    }

    modifier whenActive() {
        if (paused) revert OSC_Paused();
        _;
    }

    // -----------------------------
    // Core state
    // -----------------------------
    struct Profile {
        uint64 id;
        uint64 createdAt;
        uint64 updatedAt;
        bytes32 profileHash;
        bytes12 flair;
        uint16 flags; // bitfield for client policies
    }

    // profile registry
    uint64 public nextProfileId;
    mapping(address => uint64) public profileIdOf;
    mapping(uint64 => address) public ownerOfProfileId;
    mapping(uint64 => Profile) public profileById;

    // preference stamps
    mapping(address => uint64) public prefNonce;
    mapping(address => bytes32) public lastPrefsHash;
    mapping(address => uint64) public lastPrefsStamp;

    // swipes and matches
