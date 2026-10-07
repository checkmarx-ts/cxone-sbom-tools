# Signed SBOMs and Signature Verification

## Signing

* The purpose of this tool is to generate cryptographically signed SBOMs that follow the specification for the SBOM type.
* Signing of SBOMs is done in such a way that the resulting signature data allows the signing entity to be identified.
* The signature is created from a private key with the corresponding public key from an x509 certificate.
* The signing certificate and the public key is included in the signed SBOM.
* The SBOM signature is generated using the private key that corresponds to the public key.
* It is not possible to sign an SBOM without a private key.

## Verification

* A signed SBOM is verified with the public key corresponding to the private key that generated the SBOM's signature.
* The signer is identified by an x509 certificate that contains this relevant data:
  * The public key
  * Attributes that identify the signer
  * Identification of an authority that has signed the x509 certificate to attest that the identity
    of the signer has been confirmed
* The chain of certification for the x509 certificate will end with a trusted root CA for most verification purposes.
  This trusted root CA will generally be a public root CA so that the x509 signature chain can
  be validated with a mutually-trusted third-party.
* A bundle of the Mozilla public CAs for use with this tool can be obtained here: https://curl.se/ca/cacert.pem
* The signer's x509 certificate may have been signed by a root CA or signed by an intermediate CA.
* A bundle of intermediate CAs can be supplied along with the bundle of trusted root CAs during signature verification.
* A self-signed x509 certificate can be used to generate and validate an SBOM signature but
  is generally not appropriate for identifying and trusting the signer.
* A signature is considered valid and attributed to the signer if and only if:
  * The certificate chain of the signer can be validated by a root CA.
  * The signature of the SBOM is validated by the signer's public key.
* A signature can be valid without trusting the signer.  This only verifies the use of
  the correct public key to perform the signature validation.
