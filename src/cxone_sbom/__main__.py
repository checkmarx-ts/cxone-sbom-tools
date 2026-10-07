import importlib, sys
from .cli import execute_signing, execute_verification
from .__version__ import __version__
from .__agent__ import __agent__


def main():
    """Usage:
    cxone-sbom-tools (-h | --help | --version)
    cxone-sbom-tools sign
                    [--scanUrl URL] [--cloneUrl URL [--branch BRANCH --commit HASH] ]
                    (--cert CERTFILE) [--p-key KEYFILE] [--pass PASSWORD | --pass-env]
                    [--hash LEN] [--pretty-print | -p]
                    SBOM [OUTFILE]
    cxone-sbom-tools verify
                    (--signer CERTFILE | --embedded | --key)
                    [--ca BUNDLE] [--int BUNDLE] SBOM


    # sign

    *Signs an SBOM with the provided x509 certificate and private key.*

    **SBOM Additions**

    These optional values add entries to the externalRefs element in the SBOM

    --scanUrl URL       The URL to view the scan results.  Optional

    --cloneUrl URL      The URL to clone the code that was scanned.  Optional.

    --branch BRANCH     The name of the branch that was scanned.
                        Ignored if cloneUrl not provided.

    --commit HASH       The commit hash in the code repository of the scanned code.
                        Ignored if cloneUrl not provided.

    **Signing**

    --cert CERTFILE     A path to a PEM encoded x509 certificate or certificate bundle
                        containing the certificate and private key.

    --p-key KEYFILE     A path to a PEM encoded private key if not included in the certificate
                        bundle.

    --pass PASSWORD     The password for the private key if it is encrypted.

    --pass-env          Obtain the password for the private key from the environment variable SBOM_KEY_PASS

    --hash LEN          The SHA hash algorithm to use when signing if the public key type supports
                        setting the hash. Valid values are 256, 384, 512 [default: 256]

    --pretty-print|-p   Pretty-print the output json.[default: False]


    SBOM                A path to an SBOM input file.

    OUTFILE             A path to a file where the signed SBOM will be written.
                        Defaults to ./signed.{SBOM name}

    An exit code of 0 indicate signing was successful.  A non-zero exit code indicates an error.

    # verify

    *Verifies the identity of the signer and signature of an SBOM.*

    --signer CERTFILE   A path to a PEM encoded x509 certificate containing the signer's
                        public key for signature verification.

    --embedded          Use the signing x509 certificate embedded in the SBOM as the source
                        of the signer's public key for signature verification.

    --key               Use the public key embedded in the certificate included in the SBOM
                        to validate the SBOM signature.  This option will never return exit
                        code 0 as it will not be possible to trust the signer.

    --ca BUNDLE         Path to a file containing one or more PEM encoded trusted CA
                        x509 certificates. If not provided, it will not be possible to
                        trust the signer.

    --int BUNDLE        Path to a file containing one or more PEM encoded trusted
                        intermediate CAs. If not provided when the signer's x509
                        certificate is signed by an intermediate CA, it will not be
                        possible to trust the signer.

    SBOM                A path to an SBOM input file.

    Any signature verification operation that can't validate the certificate signing chain
    will validate the signature but will not trust the signer.  Using the x509 certificate
    embedded in the SBOM, even one that validates with a trusted signing chain,
    is possible but not recommended.

    Exit Codes:
    0: Validation success with a trusted signing chain.
    1: Signature validation failed.
    2: General failure.
    254: Signature validation successful without a trusted signing chain.
    """
    try:
        # The docopt module may not be installed unless the [cli] extra is installed
        # so load it dynamically when executing as a script.
        docopt_lib = importlib.import_module("docopt")
        docopt = docopt_lib.docopt

        args = docopt(main.__doc__, version=f"{__agent__} {__version__}")

        if args.get("sign"):
            execute_signing(args)
        elif args.get("verify"):
            execute_verification(args)

    except ModuleNotFoundError:
        print(
            "The CLI interface is not operational since it appears [cli] extra is not installed.",
            file=sys.stderr,
            flush=True,
        )
    except docopt_lib.DocoptExit as bad_args:
        print("Incorrect arguments provided.", file=sys.stderr, flush=True)
        print(bad_args, file=sys.stderr, flush=True)
    except Exception as ex:
        print(ex, file=sys.stderr, flush=True)

    exit(2)


if __name__ == "__main__":
    main()
