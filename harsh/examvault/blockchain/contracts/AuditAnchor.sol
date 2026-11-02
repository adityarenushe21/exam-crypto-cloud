// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {OrgRegistry} from "./OrgRegistry.sol";

/// @title AuditAnchor
/// @notice Anchors the off-chain, signed, hash-chained audit log on-chain in Merkle batches.
///
///  Properties enforced on-chain:
///   * Contiguity: each batch must start at lastSeq+1, so events cannot be silently skipped or dropped.
///   * Chaining: each batch records the previous batch root, so history cannot be reordered.
///   * Inclusion: anyone can verify that a given event hash is inside an anchored batch.
///   * Critical events (seal, release, revoke...) can be anchored immediately as a 1-event batch;
///     routine events are batched (hundreds per transaction).
///  Risk flags raised by the AI engine are recorded on-chain for later review; they contain only a
///  pseudonymous subject hash, a score and a hash of the explanation (no personal data).
contract AuditAnchor {
    struct Batch {
        bytes32 root;
        bytes32 prevRoot;
        uint64 firstSeq;
        uint64 lastSeq;
        uint64 timestamp;
        bool critical;
    }

    OrgRegistry public immutable registry;

    mapping(bytes32 => Batch[]) private _batches;
    mapping(bytes32 => uint64) public lastSeq;
    mapping(bytes32 => uint256) public flagCount;

    event BatchAnchored(
        bytes32 indexed orgId, uint256 indexed batchIndex, bytes32 root, bytes32 prevRoot,
        uint64 firstSeq, uint64 lastSeq, bool critical
    );
    event RiskFlagged(
        bytes32 indexed orgId, bytes32 indexed subjectHash, uint8 score, bytes32 reasonHash,
        bytes32 eventHash, uint256 flagIndex
    );

    error NotAnchorer();
    error BadRange();
    error UnknownBatch();

    constructor(OrgRegistry registry_) {
        registry = registry_;
    }

    modifier onlyAnchorer(bytes32 orgId) {
        if (!registry.hasRole(orgId, OrgRegistry.Role.Anchorer, msg.sender)) revert NotAnchorer();
        _;
    }

    function anchorBatch(bytes32 orgId, bytes32 root, uint64 firstSeq, uint64 lastSeq_, bool critical)
        external
        onlyAnchorer(orgId)
        returns (uint256 index)
    {
        if (firstSeq != lastSeq[orgId] + 1 || lastSeq_ < firstSeq || root == bytes32(0)) revert BadRange();
        Batch[] storage list = _batches[orgId];
        bytes32 prev = list.length == 0 ? bytes32(0) : list[list.length - 1].root;
        list.push(Batch(root, prev, firstSeq, lastSeq_, uint64(block.timestamp), critical));
        lastSeq[orgId] = lastSeq_;
        index = list.length - 1;
        emit BatchAnchored(orgId, index, root, prev, firstSeq, lastSeq_, critical);
    }

    function flagRisk(bytes32 orgId, bytes32 subjectHash, uint8 score, bytes32 reasonHash, bytes32 eventHash)
        external
        onlyAnchorer(orgId)
        returns (uint256 idx)
    {
        idx = ++flagCount[orgId];
        emit RiskFlagged(orgId, subjectHash, score, reasonHash, eventHash, idx);
    }

    function batchCount(bytes32 orgId) external view returns (uint256) {
        return _batches[orgId].length;
    }

    function getBatch(bytes32 orgId, uint256 index) external view returns (Batch memory) {
        if (index >= _batches[orgId].length) revert UnknownBatch();
        return _batches[orgId][index];
    }

    /// @notice leaf = keccak256(eventHash) (32-byte preimage, so it can never collide with a 64-byte internal node).
    function verifyInclusion(bytes32 orgId, uint256 index, bytes32 eventHash, bytes32[] calldata proof)
        external
        view
        returns (bool)
    {
        if (index >= _batches[orgId].length) revert UnknownBatch();
        return MerkleProof.verifyCalldata(proof, _batches[orgId][index].root, keccak256(abi.encodePacked(eventHash)));
    }
}
