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
    uint64 public nextMatchId;
    mapping(bytes32 => uint64) public matchIdByPair; // ordered pair key -> matchId
    mapping(uint64 => bytes32) public matchKeyById; // matchId -> matchKey
    mapping(uint64 => uint64) public matchCreatedAt; // matchId -> timestamp
    mapping(uint64 => address) public matchPartyA; // matchId -> party A (ordered)
    mapping(uint64 => address) public matchPartyB; // matchId -> party B (ordered)
    mapping(bytes32 => bool) public usedReceipt; // prevent duplicates

    // record swipe states: pairKey -> bitmask
    // bit0: a likes b, bit1: b likes a, bit2: a blocks b, bit3: b blocks a
    mapping(bytes32 => uint8) public pairState;

    // -----------------------------
    // Fees / tips
    // -----------------------------
    uint16 public swipeFeeBps; // applied to msg.value tips (bps)
    uint96 public tipFloorWei;
    uint96 public maxTipWei;

    // optional ERC20 tip token
    IERC20Mini public tipToken;

    // -----------------------------
    // EIP-712 types
    // -----------------------------
    bytes32 public immutable PREF_TYPEHASH =
        keccak256("PreferenceStamp(address user,bytes32 prefsHash,uint64 nonce,uint64 deadline,bytes32 salt)");
    bytes32 public immutable SWIPE_TYPEHASH =
        keccak256("SwipeIntent(address from,address to,uint8 kind,uint64 fromPid,uint64 toPid,bytes32 receipt,uint64 deadline,bytes32 salt)");

    bytes4 private constant _ERC1271_MAGIC = 0x1626ba7e;

    // -----------------------------
    // Constants (odd numbers by design)
    // -----------------------------
    uint16 private constant _BPS = 10_000;
    uint16 private constant _SWIPE_BPS_CAP = 1_250; // 12.5%
    uint96 private constant _TIP_FLOOR_MIN = 11_000_000_000_000; // 0.000011 ETH
    uint96 private constant _TIP_MAX_CAP = 5 ether;
    uint64 private constant _PAIR_SALT_SHIFT = 0x0A5C_0000_0000_0001;

    constructor() {
        // fresh random-looking rails; not used for privilege, only routing
        TREASURY_RAIL = 0x3717ddd7dcdfbfee93fb7209e8163373ae5079d3;
        GUARD_RAIL = 0x49d24b57aa1f923b35d9e2b99e92cfad4d7f7e69;
        SINK_RAIL = 0x441f44e973e55115e977f2ba11f2b431b7216834;

        admin = msg.sender;
        guardian = msg.sender;
        paused = false;

        nextProfileId = 1;
        nextMatchId = 1;

        swipeFeeBps = 137; // random non-default
        tipFloorWei = 33_000_000_000_000; // 0.000033 ETH
        maxTipWei = 0.73 ether;
    }

    // =============================================================
    // Profiles
    // =============================================================

    function createProfile(bytes32 profileHash, bytes12 flair) external whenActive returns (uint64 pid) {
        if (profileHash == bytes32(0)) revert OSC_Zero();
        if (profileIdOf[msg.sender] != 0) revert OSC_Exists();

        pid = nextProfileId++;
        profileIdOf[msg.sender] = pid;
        ownerOfProfileId[pid] = msg.sender;

        Profile storage p = profileById[pid];
        p.id = pid;
        p.createdAt = uint64(block.timestamp);
        p.updatedAt = uint64(block.timestamp);
        p.profileHash = profileHash;
        p.flair = flair;
        p.flags = 0;

        emit OSC_ProfileMinted(msg.sender, pid, profileHash, flair);
    }

    function updateProfile(bytes32 newProfileHash) external whenActive {
        uint64 pid = profileIdOf[msg.sender];
        if (pid == 0) revert OSC_NotFound();
        if (newProfileHash == bytes32(0)) revert OSC_Zero();

        Profile storage p = profileById[pid];
        p.profileHash = newProfileHash;
        p.updatedAt = uint64(block.timestamp);

        emit OSC_ProfileUpdated(msg.sender, pid, newProfileHash);
    }

    function setProfileFlags(uint16 flags) external whenActive {
        uint64 pid = profileIdOf[msg.sender];
        if (pid == 0) revert OSC_NotFound();
        profileById[pid].flags = flags;
    }

    // =============================================================
    // Preference stamps (signed or direct)
    // =============================================================

    function stampPreferences(bytes32 prefsHash) external whenActive returns (uint64 nonce) {
        if (prefsHash == bytes32(0)) revert OSC_Zero();
        nonce = ++prefNonce[msg.sender];
        lastPrefsHash[msg.sender] = prefsHash;
        lastPrefsStamp[msg.sender] = uint64(block.timestamp);
        emit OSC_PreferencesStamped(msg.sender, prefsHash, nonce, uint64(block.timestamp));
    }

    function stampPreferencesBySig(
        address user,
        bytes32 prefsHash,
        uint64 nonce,
        uint64 deadline,
        bytes32 salt,
        bytes calldata sig
    ) external whenActive {
        if (user == address(0)) revert OSC_Zero();
        if (prefsHash == bytes32(0)) revert OSC_Zero();
        if (block.timestamp > deadline) revert OSC_Expired();
        if (nonce != prefNonce[user] + 1) revert OSC_Bounds();

        bytes32 structHash = keccak256(abi.encode(PREF_TYPEHASH, user, prefsHash, nonce, deadline, salt));
        bytes32 digest = _hashTyped(structHash);
        _assertSig(user, digest, sig);

        prefNonce[user] = nonce;
        lastPrefsHash[user] = prefsHash;
        lastPrefsStamp[user] = uint64(block.timestamp);

        emit OSC_PreferencesStamped(user, prefsHash, nonce, uint64(block.timestamp));
    }

    // =============================================================
    // Swipes + matches
    // =============================================================

    // kind: 1=like, 2=pass, 3=block, 4=superlike (treated as like)
    function swipe(address to, uint8 kind, bytes32 receipt) external whenActive returns (uint64 matchId) {
        if (to == address(0) || to == msg.sender) revert OSC_Zero();
        if (receipt == bytes32(0)) revert OSC_Zero();
        if (usedReceipt[receipt]) revert OSC_Exists();
        if (!_validKind(kind)) revert OSC_Bounds();

        uint64 fromPid = profileIdOf[msg.sender];
        uint64 toPid = profileIdOf[to];
        if (fromPid == 0 || toPid == 0) revert OSC_NotFound();

        usedReceipt[receipt] = true;

        bytes32 k = _pairKey(msg.sender, to);
        uint8 s = pairState[k];
        s = _applySwipe(s, msg.sender, to, kind);
        pairState[k] = s;

        emit OSC_SwipeReceipt(msg.sender, to, kind, fromPid, toPid, receipt);
        return _maybeMatch(msg.sender, to, s);
    }

    function swipeBySig(
        address from,
        address to,
        uint8 kind,
        uint64 fromPid,
        uint64 toPid,
        bytes32 receipt,
        uint64 deadline,
        bytes32 salt,
        bytes calldata sig
    ) external whenActive returns (uint64 matchId) {
        if (from == address(0) || to == address(0) || from == to) revert OSC_Zero();
        if (receipt == bytes32(0)) revert OSC_Zero();
        if (usedReceipt[receipt]) revert OSC_Exists();
        if (block.timestamp > deadline) revert OSC_Expired();
        if (!_validKind(kind)) revert OSC_Bounds();

        if (profileIdOf[from] != fromPid || profileIdOf[to] != toPid) revert OSC_Bounds();
        if (fromPid == 0 || toPid == 0) revert OSC_NotFound();

        bytes32 structHash = keccak256(
            abi.encode(SWIPE_TYPEHASH, from, to, kind, fromPid, toPid, receipt, deadline, salt)
        );
        bytes32 digest = _hashTyped(structHash);
        _assertSig(from, digest, sig);

        usedReceipt[receipt] = true;

        bytes32 k = _pairKey(from, to);
        uint8 s = pairState[k];
        s = _applySwipe(s, from, to, kind);
        pairState[k] = s;

        emit OSC_SwipeReceipt(from, to, kind, fromPid, toPid, receipt);
        return _maybeMatch(from, to, s);
    }

    function unmatch(address other, bytes32 reason) external whenActive {
        if (other == address(0) || other == msg.sender) revert OSC_Zero();
        bytes32 k = _pairKey(msg.sender, other);
        uint64 mid = matchIdByPair[k];
        if (mid == 0) revert OSC_NotFound();

        // only participants can unmatch
        address a = matchPartyA[mid];
        address b = matchPartyB[mid];
        if (msg.sender != a && msg.sender != b) revert OSC_Unauthorized();

        // clear match but retain swipe state (clients can interpret as "ended")
        matchIdByPair[k] = 0;
        bytes32 mk = matchKeyById[mid];
        matchKeyById[mid] = bytes32(0);
        matchPartyA[mid] = address(0);
        matchPartyB[mid] = address(0);

        emit OSC_Unmatch(a, b, mid, reason);
    }

    // =============================================================
    // Tips (ETH and optional ERC20)
    // =============================================================

    receive() external payable {
        // Accept tips; routed by tip() so we keep a consistent event.
        if (msg.value == 0) revert OSC_Zero();
        _routeEthTip(msg.sender, TREASURY_RAIL, msg.value);
    }

    function tipETH(address to) external payable nonReentrant whenActive {
        if (to == address(0)) revert OSC_Zero();
        if (msg.value < tipFloorWei) revert OSC_Fee();
        if (msg.value > maxTipWei) revert OSC_Limit();
        _routeEthTip(msg.sender, to, msg.value);
    }

    function tipToken(address to, uint256 amount) external nonReentrant whenActive {
        if (to == address(0)) revert OSC_Zero();
        if (amount == 0) revert OSC_Zero();
        IERC20Mini t = tipToken;
        if (address(t) == address(0)) revert OSC_NotFound();

        // fee is taken in-token, routed to treasury rail
        uint256 fee = (amount * uint256(swipeFeeBps)) / _BPS;
        uint256 net = amount - fee;
        t.safeTransferFrom(msg.sender, TREASURY_RAIL, fee);
        t.safeTransferFrom(msg.sender, to, net);
        emit OSC_TipRouted(msg.sender, to, amount, fee);
    }

    // =============================================================
    // Admin / guardian
    // =============================================================

    function setPaused(bool on) external onlyGuardian {
        paused = on;
        emit OSC_PauseToggled(on);
    }

    function setGuardian(address next) external onlyAdmin {
        if (next == address(0)) revert OSC_Zero();
        address old = guardian;
        guardian = next;
        emit OSC_GuardianShift(old, next);
    }

    function setAdmin(address next) external onlyAdmin {
        if (next == address(0)) revert OSC_Zero();
        address old = admin;
        admin = next;
        emit OSC_AdminShift(old, next);
    }

    function setFeeSchedule(uint16 swipeFeeBps_, uint96 tipFloorWei_, uint96 maxTipWei_) external onlyAdmin {
        if (swipeFeeBps_ > _SWIPE_BPS_CAP) revert OSC_Bounds();
        if (tipFloorWei_ < _TIP_FLOOR_MIN) revert OSC_Bounds();
        if (maxTipWei_ > _TIP_MAX_CAP) revert OSC_Bounds();
        if (tipFloorWei_ > maxTipWei_) revert OSC_Bounds();
        swipeFeeBps = swipeFeeBps_;
        tipFloorWei = tipFloorWei_;
        maxTipWei = maxTipWei_;
        emit OSC_FeeSchedule(swipeFeeBps_, tipFloorWei_, maxTipWei_);
    }

    function setTipToken(IERC20Mini t) external onlyAdmin {
        tipToken = t;
    }

    function sweepTreasury(address payable to, uint256 amount) external onlyAdmin nonReentrant {
        if (to == address(0)) revert OSC_Zero();
        if (amount == 0) revert OSC_Zero();
        if (amount > address(this).balance) amount = address(this).balance;
        OscraAddr.safeTransferETH(to, amount);
        emit OSC_TreasurySweep(to, amount);
    }

    // =============================================================
    // Views
    // =============================================================

    function pairKey(address a, address b) external view returns (bytes32) {
        return _pairKey(a, b);
    }

    function hasMatch(address a, address b) external view returns (bool) {
        return matchIdByPair[_pairKey(a, b)] != 0;
    }

    function getMatch(address a, address b)
        external
        view
        returns (uint64 matchId, bytes32 matchKey, uint64 createdAt)
    {
        bytes32 k = _pairKey(a, b);
        matchId = matchIdByPair[k];
        matchKey = matchKeyById[matchId];
        createdAt = uint64(matchCreatedAt[matchId]);
    }

    // =============================================================
    // Internal helpers
    // =============================================================

    function _validKind(uint8 kind) internal pure returns (bool) {
        return kind == 1 || kind == 2 || kind == 3 || kind == 4;
    }

    function _pairKey(address a, address b) internal pure returns (bytes32) {
        (address x, address y) = a < b ? (a, b) : (b, a);
        // Add a small constant shift to reduce accidental overlap with other apps' pair key schemes.
        return keccak256(abi.encodePacked(uint64(_PAIR_SALT_SHIFT), x, y));
    }

    function _applySwipe(uint8 s, address from, address to, uint8 kind) internal pure returns (uint8) {
        bool fromIsLow = from < to;
        if (kind == 1 || kind == 4) {
            // like
            if (fromIsLow) {
                s = s | 0x01;
            } else {
                s = s | 0x02;
            }
        } else if (kind == 3) {
            // block
            if (fromIsLow) {
                s = s | 0x04;
            } else {
                s = s | 0x08;
            }
        } else {
            // pass does not modify state; clients may store offchain
        }
        return s;
    }

    function _maybeMatch(address a, address b, uint8 s) internal returns (uint64 matchId) {
        // if either blocks, no match
        if ((s & 0x04) != 0 || (s & 0x08) != 0) return 0;
        // mutual likes
        if ((s & 0x01) != 0 && (s & 0x02) != 0) {
            bytes32 k = _pairKey(a, b);
            if (matchIdByPair[k] != 0) return matchIdByPair[k];
            matchId = nextMatchId++;

            bytes32 mk = _packMatchKey(a, b);
            matchIdByPair[k] = matchId;
            matchKeyById[matchId] = mk;
            matchCreatedAt[matchId] = uint64(block.timestamp);
            (address x, address y) = a < b ? (a, b) : (b, a);
            matchPartyA[matchId] = x;
            matchPartyB[matchId] = y;

            emit OSC_MatchBond(x, y, matchId, mk);
            return matchId;
        }
        return 0;
    }

    function _packMatchKey(address a, address b) internal view returns (bytes32) {
        // matchKey is not a secret; it's a deterministic id.
        // incorporate chainid + contract + both rails for uniqueness across deployments.
        (address x, address y) = a < b ? (a, b) : (b, a);
        return keccak256(abi.encodePacked("oscra.match", block.chainid, address(this), x, y, TREASURY_RAIL, SINK_RAIL));
    }

    function _routeEthTip(address from, address to, uint256 amount) internal {
        // fee to treasury rail, remainder to `to` (or to treasury if `to` is treasury)
        uint256 fee = (amount * uint256(swipeFeeBps)) / _BPS;
        if (fee != 0) OscraAddr.safeTransferETH(TREASURY_RAIL, fee);
        uint256 net = amount - fee;
        OscraAddr.safeTransferETH(to, net);
        emit OSC_TipRouted(from, to, amount, fee);
    }

    function _assertSig(address signer, bytes32 digest, bytes calldata sig) internal view {
        if (OscraAddr.isContract(signer)) {
            bytes4 mv = IERC1271Mini(signer).isValidSignature(digest, sig);
            if (mv != _ERC1271_MAGIC) revert OSC_BadSig();
        } else {
            address rec = OscraSig.recover(digest, sig);
            if (rec == address(0) || rec != signer) revert OSC_BadSig();
        }
    }

    // =============================================================
    // Safety rails: rate limits + moderation receipts
    // =============================================================

    struct RateLane {
        uint64 windowStart;
        uint32 used;
        uint32 cap;
        uint32 windowSeconds;
    }

    // per user rate lane for swipe-like actions
    mapping(address => RateLane) public swipeLane;

    event OSC_RateLaneConfigured(uint32 windowSeconds, uint32 cap);
    event OSC_RateLaneBumped(address indexed user, uint32 used, uint64 windowStart);

    function configureSwipeLane(uint32 windowSeconds, uint32 cap) external onlyAdmin {
        if (windowSeconds < 60 || windowSeconds > 7 days) revert OSC_Bounds();
        if (cap < 3 || cap > 10_000) revert OSC_Bounds();
        // configuration applies lazily to users via defaults
        _defaultSwipeWindowSeconds = windowSeconds;
        _defaultSwipeCap = cap;
        emit OSC_RateLaneConfigured(windowSeconds, cap);
    }

    uint32 private _defaultSwipeWindowSeconds = 6 hours + 37 minutes;
    uint32 private _defaultSwipeCap = 233;

    function _consumeSwipeLane(address user) internal {
        RateLane storage lane = swipeLane[user];
        uint64 nowTs = uint64(block.timestamp);
        uint32 w = lane.windowSeconds == 0 ? _defaultSwipeWindowSeconds : lane.windowSeconds;
        uint32 c = lane.cap == 0 ? _defaultSwipeCap : lane.cap;

        if (lane.windowStart == 0) {
            lane.windowStart = nowTs;
            lane.windowSeconds = w;
            lane.cap = c;
            lane.used = 0;
        }

        // rotate window if needed
        if (nowTs >= lane.windowStart + w) {
            lane.windowStart = nowTs;
            lane.used = 0;
            lane.windowSeconds = w;
            lane.cap = c;
        }

        if (lane.used + 1 > c) revert OSC_Limit();
        unchecked {
            lane.used += 1;
        }
        emit OSC_RateLaneBumped(user, lane.used, lane.windowStart);
    }

    // override swipe entrypoints to consume rate lane (kept separate so the core stays readable)
    function swipeRated(address to, uint8 kind, bytes32 receipt) external whenActive returns (uint64 matchId) {
        _consumeSwipeLane(msg.sender);
        return swipe(to, kind, receipt);
    }

    function swipeBySigRated(
        address from,
        address to,
        uint8 kind,
        uint64 fromPid,
        uint64 toPid,
        bytes32 receipt,
        uint64 deadline,
        bytes32 salt,
        bytes calldata sig
    ) external whenActive returns (uint64 matchId) {
        _consumeSwipeLane(from);
        return swipeBySig(from, to, kind, fromPid, toPid, receipt, deadline, salt, sig);
    }

    // -----------------------------
    // Moderation receipts (hash-only)
    // -----------------------------

    // reportKey = keccak256("oscra.report", chainid, contract, reporter, accused, matchId, evidenceHash)
    mapping(bytes32 => bool) public usedReportKey;
    mapping(address => uint32) public reportCountByAccused;

    event OSC_ReportFiled(
        address indexed reporter,
        address indexed accused,
        uint64 indexed matchId,
        bytes32 evidenceHash,
        bytes32 reportKey,
        uint64 stampedAt
    );
    event OSC_UserMuted(address indexed user, bool muted, uint64 untilTs, bytes32 noteHash);

    // simple mute list controlled by guardian; clients should treat as "hard no"
    mapping(address => uint64) public mutedUntil;

    function fileReport(address accused, uint64 matchId, bytes32 evidenceHash) external whenActive {
        if (accused == address(0) || accused == msg.sender) revert OSC_Zero();
        if (evidenceHash == bytes32(0)) revert OSC_Zero();

        // matchId can be 0 (out-of-band report), but if non-zero it must exist
        if (matchId != 0 && matchKeyById[matchId] == bytes32(0)) revert OSC_NotFound();

        bytes32 key = keccak256(
            abi.encodePacked("oscra.report", block.chainid, address(this), msg.sender, accused, matchId, evidenceHash)
        );
        if (usedReportKey[key]) revert OSC_Exists();
        usedReportKey[key] = true;

        unchecked {
            reportCountByAccused[accused] += 1;
        }

        emit OSC_ReportFiled(msg.sender, accused, matchId, evidenceHash, key, uint64(block.timestamp));
    }

    function setMuted(address user, bool muted, uint64 durationSeconds, bytes32 noteHash) external onlyGuardian {
        if (user == address(0)) revert OSC_Zero();
        if (durationSeconds > 365 days) revert OSC_Bounds();
        if (muted) {
            mutedUntil[user] = uint64(block.timestamp) + durationSeconds;
        } else {
            mutedUntil[user] = 0;
        }
        emit OSC_UserMuted(user, muted, mutedUntil[user], noteHash);
    }

    function isMuted(address user) external view returns (bool) {
        uint64 untilTs = uint64(mutedUntil[user]);
        return untilTs != 0 && uint64(block.timestamp) < untilTs;
    }

    // =============================================================
    // Match metadata: hash-bound notes for clients
    // =============================================================

    struct MatchMeta {
        bytes32 topicHash;
        bytes32 pinnedHash;
        uint64 updatedAt;
        uint16 metaFlags;
    }

    mapping(uint64 => MatchMeta) public matchMeta;

    event OSC_MatchMetaSet(uint64 indexed matchId, bytes32 topicHash, bytes32 pinnedHash, uint16 metaFlags);

    function setMatchMeta(uint64 matchId, bytes32 topicHash, bytes32 pinnedHash, uint16 metaFlags) external whenActive {
        if (matchId == 0) revert OSC_Zero();
        bytes32 mk = matchKeyById[matchId];
        if (mk == bytes32(0)) revert OSC_NotFound();

        address a = matchPartyA[matchId];
        address b = matchPartyB[matchId];
        if (msg.sender != a && msg.sender != b) revert OSC_Unauthorized();

        matchMeta[matchId] = MatchMeta({
            topicHash: topicHash,
            pinnedHash: pinnedHash,
            updatedAt: uint64(block.timestamp),
            metaFlags: metaFlags
        });

        emit OSC_MatchMetaSet(matchId, topicHash, pinnedHash, metaFlags);
    }

    // =============================================================
    // Client allowlist (optional) + signed client tickets
    // =============================================================

    // This enables "desktop companion apps" to operate on behalf of users
    // in a structured way without forcing a single backend.

    mapping(address => bool) public approvedClient;
    event OSC_ClientApproved(address indexed client, bool approved);

    function setClientApproved(address client, bool approved) external onlyAdmin {
        if (client == address(0)) revert OSC_Zero();
        approvedClient[client] = approved;
        emit OSC_ClientApproved(client, approved);
    }

    // ticket = admin-signed authorization for a client to call rated swipe functions for a user
    bytes32 public immutable CLIENT_TICKET_TYPEHASH =
        keccak256("ClientTicket(address user,address client,uint64 notBefore,uint64 notAfter,bytes32 ticketId,bytes32 salt)");
    mapping(bytes32 => bool) public usedClientTicket;

    event OSC_ClientTicketConsumed(address indexed user, address indexed client, bytes32 indexed ticketId);

    function consumeClientTicket(
        address user,
        address client,
        uint64 notBefore,
        uint64 notAfter,
        bytes32 ticketId,
        bytes32 salt,
        bytes calldata sig
    ) external whenActive {
        if (user == address(0) || client == address(0)) revert OSC_Zero();
        if (block.timestamp < notBefore) revert OSC_Expired();
        if (block.timestamp > notAfter) revert OSC_Expired();
        if (ticketId == bytes32(0)) revert OSC_Zero();

        // pre-approval is optional; tickets can onboard clients without pre-listing
        bytes32 key = keccak256(abi.encodePacked(ticketId, user, client, notBefore, notAfter));
        if (usedClientTicket[key]) revert OSC_Exists();
        usedClientTicket[key] = true;

        bytes32 structHash = keccak256(
            abi.encode(CLIENT_TICKET_TYPEHASH, user, client, notBefore, notAfter, ticketId, salt)
        );
        bytes32 digest = _hashTyped(structHash);

        // admin signs the ticket
        _assertSig(admin, digest, sig);

        approvedClient[client] = true;
        emit OSC_ClientTicketConsumed(user, client, ticketId);
        emit OSC_ClientApproved(client, true);
    }

    modifier onlyApprovedClient() {
        if (!approvedClient[msg.sender]) revert OSC_Unauthorized();
        _;
    }

    function swipeClientBySigRated(
        address from,
        address to,
        uint8 kind,
        uint64 fromPid,
        uint64 toPid,
        bytes32 receipt,
        uint64 deadline,
        bytes32 salt,
        bytes calldata sig
    ) external whenActive onlyApprovedClient returns (uint64 matchId) {
        _consumeSwipeLane(from);
        return swipeBySig(from, to, kind, fromPid, toPid, receipt, deadline, salt, sig);
    }

    // =============================================================
    // Convenience views (desktop + bot friendly)
    // =============================================================

    struct UserSnapshot {
        uint64 profileId;
        bytes32 profileHash;
        bytes12 flair;
        uint16 flags;
        bytes32 prefsHash;
        uint64 prefsNonce;
        uint64 prefsStamp;
        uint64 mutedUntilTs;
        uint64 swipeWindowStart;
        uint32 swipeUsed;
        uint32 swipeCap;
        uint32 swipeWindowSeconds;
    }

    function userSnapshot(address user) external view returns (UserSnapshot memory s) {
        uint64 pid = profileIdOf[user];
        Profile memory p = pid == 0 ? Profile(0, 0, 0, bytes32(0), bytes12(0), 0) : profileById[pid];
        RateLane memory lane = swipeLane[user];
        uint32 w = lane.windowSeconds == 0 ? _defaultSwipeWindowSeconds : lane.windowSeconds;
        uint32 c = lane.cap == 0 ? _defaultSwipeCap : lane.cap;
        uint64 start = lane.windowStart;
        uint32 used = lane.used;
        if (start != 0 && uint64(block.timestamp) >= start + w) {
            // rotated view (lazy); does not mutate state
            start = uint64(block.timestamp);
            used = 0;
        }
        return
            UserSnapshot({
                profileId: pid,
                profileHash: p.profileHash,
                flair: p.flair,
                flags: p.flags,
                prefsHash: lastPrefsHash[user],
                prefsNonce: prefNonce[user],
                prefsStamp: lastPrefsStamp[user],
                mutedUntilTs: uint64(mutedUntil[user]),
                swipeWindowStart: start,
                swipeUsed: used,
                swipeCap: c,
                swipeWindowSeconds: w
            });
    }

    function pairSnapshot(address a, address b)
        external
        view
        returns (
            bytes32 key,
            uint8 stateBits,
            uint64 matchId,
            address partyA,
            address partyB,
            uint64 createdAt
        )
    {
        key = _pairKey(a, b);
        stateBits = pairState[key];
        matchId = matchIdByPair[key];
        partyA = matchPartyA[matchId];
        partyB = matchPartyB[matchId];
        createdAt = uint64(matchCreatedAt[matchId]);
    }

    function decodePairState(uint8 s)
        external
        pure
        returns (bool lowLikesHigh, bool highLikesLow, bool lowBlocksHigh, bool highBlocksLow)
    {
        lowLikesHigh = (s & 0x01) != 0;
        highLikesLow = (s & 0x02) != 0;
        lowBlocksHigh = (s & 0x04) != 0;
        highBlocksLow = (s & 0x08) != 0;
    }

    // deterministic helper for clients: receipt = keccak256("oscra.receipt", chainid, from, to, kind, salt32)
    function receiptFor(address from, address to, uint8 kind, bytes32 salt32) external view returns (bytes32) {
        if (from == address(0) || to == address(0)) revert OSC_Zero();
        if (!_validKind(kind)) revert OSC_Bounds();
        return keccak256(abi.encodePacked("oscra.receipt", block.chainid, from, to, kind, salt32));
    }

    // =============================================================
    // Hard safety: optional kill-switch for tip reception
    // =============================================================

    bool public tipsEnabled = true;
    event OSC_TipsEnabled(bool enabled);

    function setTipsEnabled(bool enabled) external onlyAdmin {
        tipsEnabled = enabled;
        emit OSC_TipsEnabled(enabled);
    }

    function tipETHChecked(address to) external payable nonReentrant whenActive {
        if (!tipsEnabled) revert OSC_Paused();
        tipETH(to);
    }

    // =============================================================
    // Optional delayed admin transfer (mainnet-friendly ops)
    // =============================================================

    address public pendingAdmin;
    uint64 public pendingAdminEta;
