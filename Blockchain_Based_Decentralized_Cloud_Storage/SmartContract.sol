// SPDX-License-Identifier: MIT
pragma solidity 0.8.11;

contract SmartContract {
    // -------------------------
    // Registration (unchanged)
    // -------------------------
    struct Register {
        uint256 timestamp;
        string data;
    }
    Register[] public register;


    // -------------------------
    // File metadata with email
    // -------------------------
    struct FileMeta {
        address owner;
        string ipfsCid;     // CID stored on-chain
        bytes32 fileHash;   // sha256(file_bytes)
        string ownerEmail;  // stored always in lowercase
        uint256 size;
        uint256 timestamp;
    }

    mapping(bytes32 => FileMeta) public files;
    bytes32[] public fileHashes;

     struct FileStatus {
        uint256 timestamp;
        string filedata;
    }
    FileStatus[] public filestatus;




    // Events
    event Registered(uint256 indexed index, address indexed author, uint256 timestamp, string data);
    event FileAdded(
        address indexed owner,
        bytes32 indexed fileHash,
        string ipfsCid,
        string ownerEmail,
        uint256 size,
        uint256 timestamp
    );
    event FileStatusCheck(uint256 indexed index, address indexed author, uint256 timestamp, string data);
    // -------------------------
    // Registration functions
    // -------------------------
    function setRegister(string memory r) public {
        require(bytes(r).length > 0, "Empty data not allowed");

        Register memory newContent = Register({
            data: r,
            timestamp: block.timestamp
        });

        register.push(newContent);
        emit Registered(register.length - 1, msg.sender, block.timestamp, r);
    }

    function getRegister() public view returns (Register[] memory) {
        return register;
    }

// -------------------------
    // file status functions
    // -------------------------
    function setFileStatus(string memory r) public {
        require(bytes(r).length > 0, "Empty data not allowed");

        FileStatus memory newContent = FileStatus({
            filedata: r,
            timestamp: block.timestamp
        });

        filestatus.push(newContent);
        emit FileStatusCheck(filestatus.length - 1, msg.sender, block.timestamp, r);
    }

    function getFileStatus() public view returns (FileStatus[] memory) {
        return filestatus;
    }



    // -------------------------
    // File storage / deduplication
    // -------------------------
    function isDuplicate(bytes32 fileHash) public view returns (bool) {
        return files[fileHash].owner != address(0);
    }

    // helper: convert ASCII uppercase letters to lowercase
    function _toLower(string memory str) internal pure returns (string memory) {
        bytes memory bStr = bytes(str);
        bytes memory bLower = new bytes(bStr.length);
        for (uint i = 0; i < bStr.length; i++) {
            // Uppercase A-Z = 65–90
            if (uint8(bStr[i]) >= 65 && uint8(bStr[i]) <= 90) {
                bLower[i] = bytes1(uint8(bStr[i]) + 32);
            } else {
                bLower[i] = bStr[i];
            }
        }
        return string(bLower);
    }

    function addFile(bytes32 fileHash, string memory ipfsCid, string memory ownerEmail, uint256 size) public {
        require(fileHash != bytes32(0), "Invalid fileHash");
        require(bytes(ipfsCid).length > 0, "Invalid CID");
        require(bytes(ownerEmail).length > 0, "Owner email required");
        require(files[fileHash].owner == address(0), "Duplicate file");

        string memory normalizedEmail = _toLower(ownerEmail);

        files[fileHash] = FileMeta({
            owner: msg.sender,
            ipfsCid: ipfsCid,
            fileHash: fileHash,
            ownerEmail: normalizedEmail,
            size: size,
            timestamp: block.timestamp
        });

        fileHashes.push(fileHash);

        emit FileAdded(msg.sender, fileHash, ipfsCid, normalizedEmail, size, block.timestamp);
    }

    function getFile(bytes32 fileHash)
        public
        view
        returns (
            address owner,
            string memory ipfsCid,
            string memory ownerEmail,
            uint256 size,
            uint256 timestamp
        )
    {
        FileMeta storage f = files[fileHash];
        return (f.owner, f.ipfsCid, f.ownerEmail, f.size, f.timestamp);
    }

    function totalFiles() public view returns (uint256) {
        return fileHashes.length;
    }

    function getFilesByOwner(string memory ownerEmail)
        public
        view
        returns (FileMeta[] memory)
    {
        string memory normalizedEmail = _toLower(ownerEmail);
        uint256 count = 0;

        // Count how many files belong to this owner
        for (uint256 i = 0; i < fileHashes.length; i++) {
            if (
                keccak256(abi.encodePacked(files[fileHashes[i]].ownerEmail)) ==
                keccak256(abi.encodePacked(normalizedEmail))
            ) {
                count++;
            }
        }

        // Collect results
        FileMeta[] memory result = new FileMeta[](count);
        uint256 j = 0;
        for (uint256 i = 0; i < fileHashes.length; i++) {
            if (
                keccak256(abi.encodePacked(files[fileHashes[i]].ownerEmail)) ==
                keccak256(abi.encodePacked(normalizedEmail))
            ) {
                result[j] = files[fileHashes[i]];
                j++;
            }
        }
        return result;
    }
}
