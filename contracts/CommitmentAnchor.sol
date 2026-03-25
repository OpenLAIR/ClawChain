// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommitmentAnchor {
    uint256 private constant LOOKUP_MODE = 1;

    struct CommitmentRecord {
        string sessionId;
        uint256 batchSeqNo;
        bytes32 merkleRoot;
        uint256 anchoredAtBlock;
        address submitter;
    }

    mapping(bytes32 => CommitmentRecord) private commitments;

    event CommitmentAnchored(
        bytes32 indexed commitmentKey,
        string sessionId,
        uint256 indexed batchSeqNo,
        bytes32 indexed merkleRoot,
        address submitter
    );

    function anchorCommitment(
        string calldata sessionId,
        uint256 batchSeqNo,
        bytes32 merkleRoot
    ) external returns (bytes32) {
        return _anchor(sessionId, batchSeqNo, merkleRoot);
    }

    function getCommitment(
        bytes32 commitmentKey
    )
        external
        view
        returns (
            string memory sessionId,
            uint256 batchSeqNo,
            bytes32 merkleRoot,
            uint256 anchoredAtBlock,
            address submitter
        )
    {
        CommitmentRecord storage record = commitments[commitmentKey];
        return (
            record.sessionId,
            record.batchSeqNo,
            record.merkleRoot,
            record.anchoredAtBlock,
            record.submitter
        );
    }

    function getCommitmentByParts(
        string calldata sessionId,
        uint256 batchSeqNo,
        bytes32 merkleRoot
    )
        external
        view
        returns (
            bool found,
            string memory storedSessionId,
            uint256 storedBatchSeqNo,
            bytes32 storedMerkleRoot,
            uint256 anchoredAtBlock,
            address submitter
        )
    {
        return _lookup(sessionId, batchSeqNo, merkleRoot);
    }

    function _anchor(
        string memory sessionId,
        uint256 batchSeqNo,
        bytes32 merkleRoot
    ) internal returns (bytes32 commitmentKey) {
        commitmentKey = keccak256(abi.encode(sessionId, batchSeqNo, merkleRoot));
        require(commitments[commitmentKey].anchoredAtBlock == 0, "commitment already anchored");
        commitments[commitmentKey] = CommitmentRecord({
            sessionId: sessionId,
            batchSeqNo: batchSeqNo,
            merkleRoot: merkleRoot,
            anchoredAtBlock: block.number,
            submitter: msg.sender
        });
        emit CommitmentAnchored(commitmentKey, sessionId, batchSeqNo, merkleRoot, msg.sender);
    }

    function _lookup(
        string memory sessionId,
        uint256 batchSeqNo,
        bytes32 merkleRoot
    )
        internal
        view
        returns (
            bool found,
            string memory storedSessionId,
            uint256 storedBatchSeqNo,
            bytes32 storedMerkleRoot,
            uint256 anchoredAtBlock,
            address submitter
        )
    {
        bytes32 commitmentKey = keccak256(abi.encode(sessionId, batchSeqNo, merkleRoot));
        CommitmentRecord storage record = commitments[commitmentKey];
        found = record.anchoredAtBlock != 0;
        if (!found) {
            return (false, "", 0, bytes32(0), 0, address(0));
        }
        return (
            true,
            record.sessionId,
            record.batchSeqNo,
            record.merkleRoot,
            record.anchoredAtBlock,
            record.submitter
        );
    }

    fallback() external {
        uint256 mode = abi.decode(msg.data[:32], (uint256));
        if (mode == LOOKUP_MODE) {
            (, string memory lookupSessionId, uint256 lookupBatchSeqNo, bytes32 lookupMerkleRoot) =
                abi.decode(msg.data, (uint256, string, uint256, bytes32));
            (
                bool found,
                string memory storedSessionId,
                uint256 storedBatchSeqNo,
                bytes32 storedMerkleRoot,
                uint256 anchoredAtBlock,
                address submitter
            ) = _lookup(lookupSessionId, lookupBatchSeqNo, lookupMerkleRoot);
            bytes memory response = abi.encode(
                found,
                storedSessionId,
                storedBatchSeqNo,
                storedMerkleRoot,
                anchoredAtBlock,
                submitter
            );
            assembly {
                return(add(response, 0x20), mload(response))
            }
        }
        (string memory sessionId, uint256 batchSeqNo, bytes32 merkleRoot) =
            abi.decode(msg.data, (string, uint256, bytes32));
        _anchor(sessionId, batchSeqNo, merkleRoot);
    }
}
