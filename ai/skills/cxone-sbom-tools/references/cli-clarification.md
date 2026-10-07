# CLI Usage Clarification

The CLI tool is installed and executable as `cxone-sbom-tools`.

Documentation for the module `cxone_sbom.__main__` or the `main()` function
is the CLI help output showing the operations and command line parameters for
those operations.  The documentation comes from the docstring on `main` and is
used by `docopt` to parse and validate the parameters.

The CLI has exit codes that can be trapped to handle outcomes of using the tool.

While the CLI can be used in a build pipeline, it may be difficult to ensure the
chain of trust is not compromised through manipulation of the pipeline
scripting. Care should be taken to ensure:

* The scan invocation was not manipulated to produce an innacurate SBOM.
* The SBOM was not modified prior to signing.
* The private key is secure from exposure or exfiltration.

## Function determination

The docstrings in `cxone_sbom.__main__` use a convention where the first
non-parameter (e.g. a command line option not prefixed by `-` or `--`)
is the function to execute.  Examples:

* `sign`
* `verify`

Other references will explain other available functions only if other
functions are available.
