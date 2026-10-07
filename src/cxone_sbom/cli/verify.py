import json, sys
from typing import Dict
from cxone_sbom.crypto import ValidationResult, SbomVerifier


def execute_verification(args: Dict) -> None:
    try:
        with open(args.get("SBOM", "rt")) as sb_in:
            loaded_sbom = json.load(sb_in)

        ca_bundle = args.get("--ca")
        int_bundle = args.get("--int")

        if args.get("--key"):
            verifier = SbomVerifier.from_embedded_key(loaded_sbom)
        elif args.get("--embedded"):
            verifier = SbomVerifier.from_embedded_cert(
                loaded_sbom, ca_bundle_pem=ca_bundle, intermediate_bundle_pem=int_bundle
            )
        else:
            verifier = SbomVerifier.from_cert_file(
                args.get("--signer"),
                ca_bundle_pem=ca_bundle,
                intermediate_bundle_pem=int_bundle,
            )

        exit(verifier.signature_validates(loaded_sbom).value)
    except Exception as ex:
        print(ex, file=sys.stderr)
        exit(1)
