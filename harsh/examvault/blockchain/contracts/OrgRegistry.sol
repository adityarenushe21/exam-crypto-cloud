// SPDX-License-Identifier: MIT
// ExamVault capstone project | Harsh Kapile | MIT World Peace University, Pune
// Module: blockchain integrity (smart contracts, chain gateway, ChronoSeal)
pragma solidity 0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title OrgRegistry
/// @notice Multi-tenant registry. Each organization (exam board, university, ...) is isolated by orgId
///         and manages its own role holders. Contains NO personal data: orgId is a hash, roles are addresses.
contract OrgRegistry is Ownable {
    enum Role { None, Controller, Analyst, Anchorer }

    struct Org {
        address admin;
        bool active;
        uint64 createdAt;
    }

    mapping(bytes32 => Org) public orgs;
    mapping(bytes32 => mapping(Role => mapping(address => bool))) private _roles;

    event OrgRegistered(bytes32 indexed orgId, address indexed admin);
    event OrgActiveSet(bytes32 indexed orgId, bool active);
    event OrgAdminTransferred(bytes32 indexed orgId, address indexed oldAdmin, address indexed newAdmin);
    event RoleGranted(bytes32 indexed orgId, Role indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed orgId, Role indexed role, address indexed account);

    error OrgExists();
    error OrgUnknown();
    error NotOrgAdmin();
    error ZeroAddress();
    error InvalidRole();

    constructor(address platformOwner) Ownable(platformOwner) {}

    function registerOrg(bytes32 orgId, address admin) external onlyOwner {
        if (admin == address(0)) revert ZeroAddress();
        if (orgs[orgId].createdAt != 0) revert OrgExists();
        orgs[orgId] = Org(admin, true, uint64(block.timestamp));
        emit OrgRegistered(orgId, admin);
    }

    function setOrgActive(bytes32 orgId, bool active) external onlyOwner {
        if (orgs[orgId].createdAt == 0) revert OrgUnknown();
        orgs[orgId].active = active;
        emit OrgActiveSet(orgId, active);
    }

    function transferOrgAdmin(bytes32 orgId, address newAdmin) external {
        Org storage o = orgs[orgId];
        if (msg.sender != o.admin) revert NotOrgAdmin();
        if (newAdmin == address(0)) revert ZeroAddress();
        emit OrgAdminTransferred(orgId, o.admin, newAdmin);
        o.admin = newAdmin;
    }

    function grantRole(bytes32 orgId, Role role, address account) external {
        if (msg.sender != orgs[orgId].admin) revert NotOrgAdmin();
        if (role == Role.None) revert InvalidRole();
        if (account == address(0)) revert ZeroAddress();
        _roles[orgId][role][account] = true;
        emit RoleGranted(orgId, role, account);
    }

    function revokeRole(bytes32 orgId, Role role, address account) external {
        if (msg.sender != orgs[orgId].admin) revert NotOrgAdmin();
        _roles[orgId][role][account] = false;
        emit RoleRevoked(orgId, role, account);
    }

    /// @dev Roles only count while the org is active.
    function hasRole(bytes32 orgId, Role role, address account) external view returns (bool) {
        return orgs[orgId].active && _roles[orgId][role][account];
    }
}
