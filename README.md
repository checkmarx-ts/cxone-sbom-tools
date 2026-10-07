# Checkmarx One SBOM Tools

This is an Python module and CLI tool for updating and signing SBOMs generated
from Checkmarx One scans.

The intended use of this tool is to produce a signed SBOMs that can be attributed
to an identified signing entity.  For this reason, an x509 certificate must be used
to provide the public key of a key pair.

## Supported SBOM Standards

### CycloneDX 1.7

This currently supports CycloneDX 1.7 JSON SBOMs.  It uses the JSF signature standard
that appears in the `signature` element of the SBOM after signing.
Signing and verification supports only a single signature.

## Installing

Installation is performed by using `pip`:

```Bash
pip install cxone-sbom-tools
```

The module can be installed directly from the release artifacts with the URL for the
install `.whl` file from the Releases:

```Bash
pip install https://github.com/checkmarx-ts/cxone-sbom-tools/releases/download/X.X.X/cxone_sbom-X.X.X-py3-none-any.whl
```

To use the CLI, installing with the `[cli]` extra is required to use the CLI interface.  This can be done with one of the
following options:

```Bash
pip install "cxone_sbom[cli]@https://github.com/checkmarx-ts/cxone-sbom-tools/releases/download/X.X.X/cxone_sbom-X.X.X-py3-none-any.whl"
```

```Bash
pip install cxone-sbom-tools[cli]
```

## Using the CLI

Execute `cxone-sbom-tools -h` for a list of command line options.  An AI skill can be downloaded from the release artifacts
to assist with explaining the command line execution.

## Using the API

A PDF of the API documentation is available for download.  An AI skill can be downloaded from the release artifacts to
assist with generating code examples for using the API.
