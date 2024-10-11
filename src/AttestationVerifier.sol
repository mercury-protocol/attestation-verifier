// SPDX-License-Identifier: GLP-3.0
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./utils/Asn1Decode.sol";
import "./utils/Algorithm.sol";
import "./utils/DateTime.sol";
import "./utils/BytesUtils.sol";
import "./utils/Base64.sol";
import "./IAttestationVerifier.sol";

/**
@title Attestation Verifier
@author Lajos Deme, Mercury Protocol
@notice Helper contract for the verification of Intel SGX attestations.
 */
contract AttestationVerifier is IAttestationVerifier, Ownable {
    using Asn1Decode for bytes;
    using BytesUtils for bytes;

    bytes32 public EXPECTED_MRENCLAVE = 0x3de47aea313c51d32b98c39a135f6c7fdc4999d05991585fa378bc8d22aef842;

    /** 
        @dev A succesfully verified enclave attestation report always contains the same bytes at the same position.
        These bytes stand for "isvEnclaveQuoteStatus":"OK" which is always part of the report.  
     */
    bytes32 okBytes =
        0x22697376456e636c61766551756f7465537461747573223a224f4b2200000000;

    /**
        @dev The public key of the Attestation Report Signing CA Certificate.
        All Attestation Report Signing certificates must be traced back to this root to be considered valid.
        To verify that the key is valid, first verify the rootCert using the official certificate downloaded from Intel,
        then verify this key against that certificate.
     */
    bytes public caCertPubKey;

    /**
        @dev The Attestation Report Signing CA Certificate.
        This certificate can be downloaded from Intel.
        To verify that this certificate is correct check that it is identical to the one retrieved from Intel.
     */
    bytes public rootCert;

    /** @dev The algorithm used for signing & verifying. */
    Algorithm public sha256WithRSAEncryption;

    bytes23 public isvEnclaveQuoteBodyStart = 0x22697376456e636c61766551756f7465426f6479223a22; // "isvEnclaveQuoteBody":"

    constructor(
        bytes memory _caCertPubKey,
        bytes memory _rootCert,
        Algorithm _algo
    ) Ownable(msg.sender) {
        caCertPubKey = _caCertPubKey;
        rootCert = _rootCert;
        sha256WithRSAEncryption = _algo;
    }

    /** @dev See IAttestationVerifier - verifyAttestation */
    function verifyAttestation(
        bytes calldata attCert,
        bytes calldata attBody,
        bytes calldata attSig
    ) public view returns (bool) {
        bytes memory intermediatePubKey = verifyCert(attCert, caCertPubKey);
        // 5. verify data & signature with intermediate pub key
        if (sha256WithRSAEncryption.verify(intermediatePubKey, attBody, attSig) == false) {
            return false;
        }
        // TODO: 6. verify quote status OK
        /* if (verifyAttBodyOk(attBody) == false) {
            return false;
        } */

        bytes32 mrenclave = getMrEnclave(attBody);
        
        return EXPECTED_MRENCLAVE == mrenclave;
    }

    /**
    @dev Parses and verifies a X.509 certificate.
    @param cert The X.509 certificate to verify.
    @param pubKey The public key of the certificate that signed this certificate.
     */
    function verifyCert(bytes memory cert, bytes memory pubKey)
        public
        view
        returns (bytes memory certPubKey)
    {
        uint256 node1;
        uint256 node2;
        uint256 node3;

        node1 = cert.root();
        node1 = cert.firstChildOf(node1);
        node2 = cert.firstChildOf(node1);
        if (cert[NodePtr.ixs(node2)] == 0xa0) {
            node2 = cert.nextSiblingOf(node2);
        }

        node2 = cert.nextSiblingOf(node2);
        node2 = cert.firstChildOf(node2);
        node3 = cert.nextSiblingOf(node1);
        node3 = cert.nextSiblingOf(node3);
        // Verify signature
        require(
            sha256WithRSAEncryption.verify(
                pubKey,
                cert.allBytesAt(node1),
                cert.bytesAt(node3)
            ),
            "AttestationVerifier: Signature doesnt match"
        );

        // Verify validNotBefore
        node1 = cert.firstChildOf(node1);
        node1 = cert.nextSiblingOf(node1);
        node1 = cert.nextSiblingOf(node1);
        node1 = cert.nextSiblingOf(node1);
        node1 = cert.nextSiblingOf(node1);

        node2 = cert.firstChildOf(node1);

        uint40 validNotBefore = uint40(
            DateTime.toTimestamp(cert.bytesAt(node2))
        );
        require(
            validNotBefore <= block.timestamp,
            "AttestationVerify: Certificate is not yet valid."
        );

        // Verify validNotAfter
        node2 = cert.nextSiblingOf(node2);
        uint40 validNotAfter = uint40(
            DateTime.toTimestamp(cert.bytesAt(node2))
        );
        require(
            validNotAfter >= block.timestamp,
            "AttestationVerify: Certificate expired."
        );

        // get pubkey from cert
        node1 = cert.nextSiblingOf(node1);
        node1 = cert.nextSiblingOf(node1);

        certPubKey = cert.allBytesAt(node1);
    }

    /**
    @dev Verifies that the isvEnclaveQuoteStatus value from the report is "OK".
    @param attBody The body of the verification report response.
    @return bool True if the status is OK, false otherwise.
     */
    function verifyAttBodyOk(bytes calldata attBody)
        internal
        view
        returns (bool)
    {
        if (attBody.length < 128) return false;

        bytes32 statusBytes = attBody.readBytesN(101, 28);
        return statusBytes == okBytes;
    }

    function getMrEnclave(bytes calldata attBody) public view returns (bytes32) {
        bytes memory decodedIsvEnclaveQuoteBody = getBytesAfterSequence(attBody, isvEnclaveQuoteBodyStart);
        bytes32 mrenclave = decodedIsvEnclaveQuoteBody.readBytesN(112, 32);
        return mrenclave;
    }

    function getBytesAfterSequence(bytes memory data, bytes23 sequence) internal pure returns (bytes memory) {
        uint256 startIndex = indexOf(data, sequence) + sequence.length;

        uint256 length = data.length - startIndex;
        uint256 newLength = 0;

        bytes memory result = new bytes(length);

        for (uint256 i = 0; i < length; i++) {
            if (data[startIndex + i] == 0x22) {
                break;
            }
            result[i] = data[startIndex + i];
            newLength++;
        }

        bytes memory newResult = new bytes(newLength);
        for (uint256 i = 0; i < newLength; i++) {
            newResult[i] = result[i];
        }

        string memory resultString = string(newResult);
        bytes memory decodedResult = Base64.decode(resultString);
        return decodedResult;
    }

    function indexOf(bytes memory haystack, bytes23 needle) internal pure returns (uint256) {
            uint256 needleLength = needle.length;
            uint256 haystackLength = haystack.length;

            if (needleLength > haystackLength) {
                return type(uint256).max;
            }

            for (uint256 i = 0; i <= haystackLength - needleLength; i++) {
                bool found = true;
                for (uint256 j = 0; j < needleLength; j++) {
                    if (haystack[i + j] != needle[j]) {
                        found = false;
                        break;
                    }
                }

                if (found) {
                    return i;
                }
            }

            return type(uint256).max;
    }

    function setExpectedMrEnclave(bytes32 _expectedMrEnclave) external onlyOwner {
        require(_expectedMrEnclave != bytes32(0), "Expected MRENCLAVE can't be set to zero bytes");
        EXPECTED_MRENCLAVE = _expectedMrEnclave;
    }
}