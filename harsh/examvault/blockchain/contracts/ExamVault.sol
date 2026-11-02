// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {OrgRegistry} from "./OrgRegistry.sol";

/// @title ExamVault
/// @notice On-chain half of the "ChronoSeal" protocol.
///
///  What this contract DOES enforce:
///   * A paper is sealed with an immutable commitment (Merkle root of per-centre encrypted variants,
///     root of Shamir-share commitments) and a release time.
///   * Custodians can only approve release AFTER releaseTime. Release needs `threshold` distinct custodians.
///   * Emergency actions (freeze, unfreeze, reschedule, revoke+backup, custodian rotation, mark-compromised)
///     are custodian-voted proposals with asymmetric thresholds (freeze is easier than unfreeze).
///   * Anyone can verify a variant / share commitment via Merkle proofs (public verification page).
///
///  What it deliberately does NOT do: hold any secret. The paper key (DEK) is Shamir-split off-chain; this
///  contract only decides WHEN custodians' clients are allowed to act. No personal data is stored on-chain.
contract ExamVault {
    enum Status { None, Sealed, Frozen, Released, Revoked, Compromised }
    enum Action { Freeze, Unfreeze, Reschedule, Revoke, RotateCustodian, MarkCompromised }

    struct Paper {
        bytes32 orgId;
        bytes32 manifestRoot;     // Merkle root of per-centre variant commitments
        bytes32 shareCommitRoot;  // Merkle root of (custodian, sha256(share)) commitments
        bytes32 masterHash;       // SHA-256 of the sealed master package (hash of encrypted paper, per synopsis)
        uint64 sealedAt;
        uint64 releaseTime;
        uint64 releasedAt;
        uint32 round;             // bumped on every state change that must invalidate pending votes/approvals
        uint8 threshold;
        uint8 freezeThreshold;
        Status status;
        address[] custodians;
    }

    struct SealParams {
        bytes32 orgId;
        bytes32 paperId;
        bytes32 manifestRoot;
        bytes32 shareCommitRoot;
        bytes32 masterHash;
        uint64 releaseTime;
        uint8 threshold;
        uint8 freezeThreshold;
        address[] custodians;
    }

    struct Proposal {
        bytes32 paperId;
        Action action;
        address proposer;
        uint64 createdAt;
        uint64 expiresAt;
        uint32 round;
        uint8 votes;
        bool executed;
        uint64 newTime;   // Reschedule
        address oldC;     // RotateCustodian
        address newC;     // RotateCustodian
        bytes32 aux;      // Revoke: backup paperId | RotateCustodian: new shareCommitRoot
    }

    OrgRegistry public immutable registry;
    uint64 public immutable proposalTtl;
    uint8 public constant MAX_CUSTODIANS = 16;

    mapping(bytes32 => Paper) private _papers;
    mapping(bytes32 => bytes32) public supersededBy; // revoked paper => backup paper
    mapping(bytes32 => mapping(uint32 => mapping(address => bool))) private _releaseVoted;
    mapping(bytes32 => mapping(uint32 => uint8)) public releaseApprovals;

    mapping(uint256 => Proposal) private _proposals;
    mapping(uint256 => mapping(address => bool)) private _proposalVoted;
    uint256 public proposalCount;

    event PaperSealed(
        bytes32 indexed orgId, bytes32 indexed paperId, bytes32 manifestRoot, bytes32 shareCommitRoot,
        bytes32 masterHash, uint64 releaseTime, uint8 threshold, uint8 freezeThreshold, address[] custodians
    );
    event ReleaseApproved(bytes32 indexed paperId, address indexed custodian, uint32 round, uint8 approvals);
    event ReleaseAuthorized(bytes32 indexed paperId, uint32 round, uint64 at);
    event ProposalCreated(uint256 indexed id, bytes32 indexed paperId, Action indexed action, address proposer, uint64 expiresAt);
    event ProposalVoted(uint256 indexed id, address indexed voter, uint8 votes);
    event ProposalExecuted(uint256 indexed id, bytes32 indexed paperId, Action indexed action);
    event PaperFrozen(bytes32 indexed paperId);
    event PaperUnfrozen(bytes32 indexed paperId);
    event PaperRescheduled(bytes32 indexed paperId, uint64 oldTime, uint64 newTime);
    event PaperRevoked(bytes32 indexed paperId, bytes32 indexed backupPaperId);
    event CustodianRotated(bytes32 indexed paperId, address indexed oldC, address indexed newC, bytes32 newShareCommitRoot);
    event PaperCompromised(bytes32 indexed paperId);

    error NotController();
    error NotAnalyst();
    error NotCustodian();
    error NotAuthorizedToPropose();
    error PaperExists();
    error PaperUnknown();
    error BadState();
    error BadParam();
    error TooEarly(uint64 releaseTime, uint64 nowTs);
    error AlreadyVoted();
    error NoProposal();
    error AlreadyExecuted();
    error Expired();
    error Stale();

    constructor(OrgRegistry registry_, uint64 proposalTtl_) {
        registry = registry_;
        proposalTtl = proposalTtl_;
    }

    // ───────────────────────────── Sealing ─────────────────────────────

    function sealPaper(SealParams calldata s) external {
        if (!registry.hasRole(s.orgId, OrgRegistry.Role.Controller, msg.sender)) revert NotController();
        if (_papers[s.paperId].sealedAt != 0) revert PaperExists();
        uint256 n = s.custodians.length;
        if (
            s.releaseTime <= block.timestamp || n > MAX_CUSTODIANS || s.threshold < 2 || s.threshold > n ||
            s.freezeThreshold < 1 || s.freezeThreshold > s.threshold || s.manifestRoot == bytes32(0)
        ) revert BadParam();

        for (uint256 i = 0; i < n; i++) {
            if (s.custodians[i] == address(0)) revert BadParam();
            for (uint256 j = 0; j < i; j++) {
                if (s.custodians[j] == s.custodians[i]) revert BadParam();
            }
        }

        Paper storage p = _papers[s.paperId];
        p.orgId = s.orgId;
        p.manifestRoot = s.manifestRoot;
        p.shareCommitRoot = s.shareCommitRoot;
        p.masterHash = s.masterHash;
        p.sealedAt = uint64(block.timestamp);
        p.releaseTime = s.releaseTime;
        p.threshold = s.threshold;
        p.freezeThreshold = s.freezeThreshold;
        p.status = Status.Sealed;
        p.custodians = s.custodians;

        emit PaperSealed(
            s.orgId, s.paperId, s.manifestRoot, s.shareCommitRoot, s.masterHash,
            s.releaseTime, s.threshold, s.freezeThreshold, s.custodians
        );
    }

    // ───────────────────────── Time-gated release ─────────────────────────

    /// @notice Custodian approves release. Reverts before releaseTime: the time-lock is a protocol rule,
    ///         not a policy. At `threshold` approvals the paper moves to Released and custodians' clients
    ///         re-encrypt their key shares to the centre.
    function approveRelease(bytes32 paperId) external {
        Paper storage p = _paper(paperId);
        if (p.status != Status.Sealed) revert BadState();
        if (block.timestamp < p.releaseTime) revert TooEarly(p.releaseTime, uint64(block.timestamp));
        if (!_isCustodian(p, msg.sender)) revert NotCustodian();
        if (_releaseVoted[paperId][p.round][msg.sender]) revert AlreadyVoted();

        _releaseVoted[paperId][p.round][msg.sender] = true;
        uint8 count = ++releaseApprovals[paperId][p.round];
        emit ReleaseApproved(paperId, msg.sender, p.round, count);

        if (count >= p.threshold) {
            p.status = Status.Released;
            p.releasedAt = uint64(block.timestamp);
            emit ReleaseAuthorized(paperId, p.round, uint64(block.timestamp));
        }
    }

    // ───────────────────── Emergency proposals (custodian-voted) ─────────────────────

    function propose(
        bytes32 paperId,
        Action action,
        uint64 newTime,
        address oldC,
        address newC,
        bytes32 aux
    ) external returns (uint256 id) {
        Paper storage p = _paper(paperId);

        if (action == Action.MarkCompromised) {
            // Post-release leak: an analyst must initiate (evidence-based), custodians must confirm.
            if (!registry.hasRole(p.orgId, OrgRegistry.Role.Analyst, msg.sender)) revert NotAnalyst();
        } else if (!_isCustodian(p, msg.sender) && !registry.hasRole(p.orgId, OrgRegistry.Role.Controller, msg.sender)) {
            revert NotAuthorizedToPropose();
        }

        id = ++proposalCount;
        Proposal storage pr = _proposals[id];
        pr.paperId = paperId;
        pr.action = action;
        pr.proposer = msg.sender;
        pr.createdAt = uint64(block.timestamp);
        pr.expiresAt = uint64(block.timestamp) + proposalTtl;
        pr.round = p.round;
        pr.newTime = newTime;
        pr.oldC = oldC;
        pr.newC = newC;
        pr.aux = aux;
        _precheck(p, pr); // fail fast on impossible proposals

        emit ProposalCreated(id, paperId, action, msg.sender, pr.expiresAt);

        // A custodian proposer implicitly votes for their own proposal.
        if (_isCustodian(p, msg.sender)) _vote(id, msg.sender);
    }

    function voteProposal(uint256 id) external {
        _vote(id, msg.sender);
    }

    function _vote(uint256 id, address voter) internal {
        Proposal storage pr = _proposals[id];
        if (pr.createdAt == 0) revert NoProposal();
        if (pr.executed) revert AlreadyExecuted();
        if (block.timestamp > pr.expiresAt) revert Expired();
        Paper storage p = _papers[pr.paperId];
        if (pr.round != p.round) revert Stale();
        if (!_isCustodian(p, voter)) revert NotCustodian();
        if (_proposalVoted[id][voter]) revert AlreadyVoted();

        _proposalVoted[id][voter] = true;
        pr.votes += 1;
        emit ProposalVoted(id, voter, pr.votes);

        uint8 required = pr.action == Action.Freeze ? p.freezeThreshold : p.threshold;
        if (pr.votes >= required) _execute(id, pr, p);
    }

    function _execute(uint256 id, Proposal storage pr, Paper storage p) internal {
        _precheck(p, pr); // state may have changed since proposal creation
        pr.executed = true;
        Action a = pr.action;
        bytes32 paperId = pr.paperId;

        if (a == Action.Freeze) {
            p.status = Status.Frozen;
            emit PaperFrozen(paperId);
        } else if (a == Action.Unfreeze) {
            p.status = Status.Sealed;
            emit PaperUnfrozen(paperId);
        } else if (a == Action.Reschedule) {
            uint64 old = p.releaseTime;
            p.releaseTime = pr.newTime;
            emit PaperRescheduled(paperId, old, pr.newTime);
        } else if (a == Action.Revoke) {
            p.status = Status.Revoked;
            supersededBy[paperId] = pr.aux;
            emit PaperRevoked(paperId, pr.aux);
        } else if (a == Action.RotateCustodian) {
            for (uint256 i = 0; i < p.custodians.length; i++) {
                if (p.custodians[i] == pr.oldC) {
                    p.custodians[i] = pr.newC;
                    break;
                }
            }
            p.shareCommitRoot = pr.aux;
            emit CustodianRotated(paperId, pr.oldC, pr.newC, pr.aux);
        } else {
            p.status = Status.Compromised;
            emit PaperCompromised(paperId);
        }

        p.round += 1; // invalidates every other pending proposal and partial release approvals
        emit ProposalExecuted(id, paperId, a);
    }

    function _precheck(Paper storage p, Proposal storage pr) internal view {
        Action a = pr.action;
        Status s = p.status;
        bool preRelease = (s == Status.Sealed || s == Status.Frozen);

        if (a == Action.Freeze) {
            if (s != Status.Sealed) revert BadState();
        } else if (a == Action.Unfreeze) {
            if (s != Status.Frozen) revert BadState();
        } else if (a == Action.Reschedule) {
            if (!preRelease) revert BadState();
            if (pr.newTime <= p.releaseTime || pr.newTime <= block.timestamp) revert BadParam(); // later only
        } else if (a == Action.Revoke) {
            if (!preRelease) revert BadState();
            Paper storage b = _papers[pr.aux];
            if (pr.aux == pr.paperId || b.status != Status.Sealed || b.orgId != p.orgId) revert BadParam();
        } else if (a == Action.RotateCustodian) {
            if (!preRelease) revert BadState();
            if (pr.newC == address(0) || !_isCustodian(p, pr.oldC) || _isCustodian(p, pr.newC)) revert BadParam();
        } else {
            if (s != Status.Released) revert BadState();
        }
    }

    // ───────────────────────────── Views ─────────────────────────────

    function getPaper(bytes32 paperId) external view returns (Paper memory) {
        return _paper(paperId);
    }

    function getProposal(uint256 id) external view returns (Proposal memory) {
        return _proposals[id];
    }

    function custodiansOf(bytes32 paperId) external view returns (address[] memory) {
        return _paper(paperId).custodians;
    }

    function hasVotedRelease(bytes32 paperId, address c) external view returns (bool) {
        return _releaseVoted[paperId][_paper(paperId).round][c];
    }

    function canApproveRelease(bytes32 paperId) external view returns (bool) {
        Paper storage p = _paper(paperId);
        return p.status == Status.Sealed && block.timestamp >= p.releaseTime;
    }

    /// @notice Public verification: was this centre's encrypted variant part of the sealed manifest?
    function verifyVariant(
        bytes32 paperId, bytes32 centreIdHash, bytes32 variantHash, bytes32[] calldata proof
    ) external view returns (bool) {
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(centreIdHash, variantHash))));
        return MerkleProof.verifyCalldata(proof, _paper(paperId).manifestRoot, leaf);
    }

    /// @notice Verifiable shares: lets a custodian prove the share they hold matches the sealed commitment.
    function verifyShareCommitment(
        bytes32 paperId, address custodian, bytes32 shareHash, bytes32[] calldata proof
    ) external view returns (bool) {
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(custodian, shareHash))));
        return MerkleProof.verifyCalldata(proof, _paper(paperId).shareCommitRoot, leaf);
    }

    // ─────────────────────────── Internal ───────────────────────────

    function _paper(bytes32 paperId) internal view returns (Paper storage p) {
        p = _papers[paperId];
        if (p.sealedAt == 0) revert PaperUnknown();
    }

    function _isCustodian(Paper storage p, address a) internal view returns (bool) {
        uint256 n = p.custodians.length;
        for (uint256 i = 0; i < n; i++) {
            if (p.custodians[i] == a) return true;
        }
        return false;
    }
}
