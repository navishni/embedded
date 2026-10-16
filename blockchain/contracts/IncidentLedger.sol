// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IncidentLedger
/// @notice Tamper-evident, append-only log of intrusion incidents.
///         Only metadata and the SHA-256 hash of the evidence image are stored
///         on-chain; the encrypted image itself stays off-chain.
contract IncidentLedger {
    struct Incident {
        uint64 timestamp;      // capture time reported by the backend (unix seconds)
        uint64 blockTime;      // block timestamp when recorded
        address recorder;      // backend account that wrote the record
        bytes32 evidenceHash;  // SHA-256 of the plaintext JPEG
        string cameraId;
        bool exists;
    }

    address public owner;
    mapping(address => bool) public recorders;
    mapping(bytes32 => Incident) private incidents;   // keccak256(incidentId) => record
    string[] private incidentIds;

    event IncidentRecorded(string incidentId, string cameraId, uint64 timestamp,
                           bytes32 evidenceHash, address indexed recorder);
    event RecorderUpdated(address indexed account, bool allowed);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error NotRecorder();
    error AlreadyRecorded(string incidentId);
    error InvalidInput();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyRecorder() {
        if (!recorders[msg.sender]) revert NotRecorder();
        _;
    }

    constructor() {
        owner = msg.sender;
        recorders[msg.sender] = true;
        emit RecorderUpdated(msg.sender, true);
    }

    function setRecorder(address account, bool allowed) external onlyOwner {
        recorders[account] = allowed;
        emit RecorderUpdated(account, allowed);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert InvalidInput();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Record an incident. Records can never be changed or deleted.
    function recordIncident(
        string calldata incidentId,
        uint64 timestamp,
        string calldata cameraId,
        bytes32 evidenceHash
    ) external onlyRecorder {
        if (bytes(incidentId).length == 0 || evidenceHash == bytes32(0)) revert InvalidInput();
        bytes32 key = keccak256(bytes(incidentId));
        if (incidents[key].exists) revert AlreadyRecorded(incidentId);

        incidents[key] = Incident({
            timestamp: timestamp,
            blockTime: uint64(block.timestamp),
            recorder: msg.sender,
            evidenceHash: evidenceHash,
            cameraId: cameraId,
            exists: true
        });
        incidentIds.push(incidentId);
        emit IncidentRecorded(incidentId, cameraId, timestamp, evidenceHash, msg.sender);
    }

    function getIncident(string calldata incidentId)
        external
        view
        returns (bool exists, uint64 timestamp, string memory cameraId, bytes32 evidenceHash,
                 address recorder, uint64 blockTime)
    {
        Incident storage inc = incidents[keccak256(bytes(incidentId))];
        return (inc.exists, inc.timestamp, inc.cameraId, inc.evidenceHash, inc.recorder, inc.blockTime);
    }

    /// @notice Convenience check: does `evidenceHash` match the recorded hash?
    function verifyEvidence(string calldata incidentId, bytes32 evidenceHash) external view returns (bool) {
        Incident storage inc = incidents[keccak256(bytes(incidentId))];
        return inc.exists && inc.evidenceHash == evidenceHash;
    }

    function incidentCount() external view returns (uint256) {
        return incidentIds.length;
    }

    function incidentIdAt(uint256 index) external view returns (string memory) {
        return incidentIds[index];
    }
}
