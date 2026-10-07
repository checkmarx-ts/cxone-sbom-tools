import os, json, sys
from pathlib import Path
from typing import Dict
from cxone_sbom.crypto import HashAlgorithm, SbomSigner, RepositoryInfo


def __repo_from_args(args: Dict) -> None | RepositoryInfo:
    if args.get("--cloneUrl") is None:
        return None
    else:
        return RepositoryInfo(
            cloneUrl=args.get("--cloneUrl"),
            branch=args.get("--branch"),
            commit=args.get("--commit"),
        )


def execute_signing(args: Dict) -> None:
    try:
        hashalg = HashAlgorithm(args.get("--hash"))
        optionals = {
            "scanUrl": args.get("--scanUrl"),
            "repository": __repo_from_args(args),
        }

        password = args.get("--pass") or os.environ.get("SBOM_KEY_PASS")

        sbom_path = Path(args.get("SBOM"))
        if not args.get("OUTFILE"):
            out_path = Path(f"./signed.{sbom_path.name}")
        else:
            out_path = Path(args.get("OUTFILE"))

        pretty_print = None if not args.get("--pretty-print") else 2

        with open(sbom_path, "rt") as sb_in:
            loaded_sbom = json.load(sb_in)

        if args.get("--p-key"):
            # Not bundle
            signer = SbomSigner.from_cert_files(
                args.get("--cert"),
                private_key_pem=args.get("--p-key"),
                password=password,
                hash=hashalg,
            )
        else:
            # Bundle
            signer = SbomSigner.from_cert_bundle(
                args.get("--cert"), password=password, hash=hashalg
            )

        with open(out_path, "wt") as sb_out:
            json.dump(
                signer.sign_sbom(loaded_sbom, **optionals), sb_out, indent=pretty_print
            )

        exit(0)
    except Exception as ex:
        print(ex, file=sys.stderr)
        exit(1)
