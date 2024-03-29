# Attestation Verifier  
Intel SGX Attestation Report verification on-chain.  

The identity and validity of secure enclaves can be verified using the Intel Attestation Service. As a result of this process an Attestation Verification Report is generated. The smart contracts in this repository handle the verification of these reports on-chain.  
The verification process looks like this:
1. decoding and verifying the Report Signing Certificate Chain. Verifying that the chain is rooted in a trusted Report Signing CA Cerficiate (available from Intel).
2. Verify the signature over the report using the Attestation Report Signing Certificate.
3. Verify the content of the report.

Since these are all compute intensive steps, it is infeasible to use L1 for this purpose. With Scroll L2 we were able to achieve speed, scale, and reduced costs.

Attestation Verifier on Mumbai testnet: 0x28901af16E9aC082a8489eEc6c1D073913Fc8c67  
RSASHA256 Algorithm on Mumbai testnet: 0x0f22f7A4765e2Ec01F3a0e48bF8F68336b8597c5  
