// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

interface IAttestationVerifier {
    /**
    @notice Represents an Intel Attestation Verification Report.
    @param cert The Attestation Report Signing Certificate.
    @param body The body of the Attestation Verification Report.
    @param sig X-IASReport-Signature. Signature signed by the Report Signing Key over the body of the report.
     */
    struct Attestation {
        bytes cert;
        bytes body;
        bytes sig;
    }

    /**
    @notice Verifies the validity of an an Intel Attestation Verification Report.
    All of these values are obtained from the HTTP response of an attestation verification request made to Intel.
    For more info: https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf
    @param attCert Attestation Report Signing Certificate.
    @param attBody The entire body of the HTTP response in hex.
    @param attSig X-IASReport-Signature.
     */
    function verifyAttestation(
        bytes calldata attCert,
        bytes calldata attBody,
        bytes calldata attSig
    ) external returns (bool);
}