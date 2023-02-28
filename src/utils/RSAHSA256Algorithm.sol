// SPDX-License-Identifier: UNLICENSED
// Author: ENS Domains
pragma solidity ^0.8.4;

import "./Algorithm.sol";
import "./BytesUtils.sol";
import "./RSAVerify.sol";
import "./Asn1Decode.sol";

contract RsaSha256Algorithm is Algorithm {
  using BytesUtils for bytes;
  using Asn1Decode for bytes;
  using NodePtr for uint;

  function verify(bytes calldata key, bytes calldata data, bytes calldata sig)
  external view returns (bool)
  {
    bool ok;
    bytes memory result;
    bytes memory m;
    bytes memory e;

    (m, e) = extractKeyComponents(key);

    (ok, result) = RSAVerify.rsarecover(m, e, sig);

    return ok && sha256(data) == result.readBytes32(result.length - 32);
  }

  /**
   * @dev Extracts modulus and exponent (respectively) from a DER-encoded RSA public key
   * @param key A DER-encoded RSA public key
   */
  function extractKeyComponents(bytes memory key)
  public pure returns (bytes memory, bytes memory)
  {
    bytes32 oid;
    uint node;
    bytes memory modulus;
    bytes memory exponent;

    node = key.root();
    node = key.firstChildOf(node);
    // OID must be 1.2.840.113549.1.1.1 (rsaEncryption)
    oid = keccak256(key.bytesAt(key.firstChildOf(node)));
    require(oid == 0x3be606946d6f343b24d5ecdbd7e3370a5303ed54845f50f466a35f3bbeb46a45, "Invalid key");

    node = key.nextSiblingOf(node);
    node = key.rootOfBitStringAt(node);
    node = key.firstChildOf(node);
    modulus = key.uintBytesAt(node);
    node = key.nextSiblingOf(node);
    exponent = key.uintBytesAt(node);

    return (modulus, exponent);
  }
}