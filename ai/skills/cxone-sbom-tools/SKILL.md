---
name: cxone-sbom-tools
description: Documentation and help for cxone-sbom-tools CLI and API.
---

# Checkmarx One SBOM Tools

This is a Python module that has an optional CLI component.  With this
module, SBOMs can be cryptographically signed and signature validation
can be performed for signed SBOMs.

Reference `references/README.md` to understand the scope, purpose, and general
installation instructions for `cxone-sbom-tools`.  For clarifications
about content found in `README.md`, reference `references/readme-clarification.md`.

Reference `references/install.md` to understand:
* The version number of the current release that generated this skill.
  * Use the version number in `references/install.md` for references by humans.  The
    version on the wheel is a PEP 440 version that is equivalent to the human version
    in cases of a prerelease and identical for a release.
* The `pip` installation instructions with and without the CLI option.
* The location of the artifacts that should be used when instructing the user to obtain
  artifacts.

Reference `references/cxone-sbom-tools-docs.md` for CLI and API documentation.

## Use-Case #1: Produce code snippets showing how to call the API

Reference `references/api-clarification.md` about rendering code snippets
that use the API.  The reference `references/cxone-sbom-tools-docs.md` has the
API documentation.

When producing a code snippet, check the following before output:

* If this is the first rendered API example of the conversation, also include instructions
  to update `requirements.txt` to install `cxone-sbom-tools` as a module with the PEP 508
  form.  This should not include instructions about installing the CLI option.
* Include the module imports.
* For examples that are not integrated with existing code:
  * Add a basic driver function that executes if the file is executed with Python.
  * Provide stub variables that have upper-case values to indicate the user needs to provide
    a path to an input.  Example:

  ```Python
  x509_cert = "PATH/TO/YOUR/cert.pem GOES HERE"
  sbom = "PATH/TO/YOUR/sbom.json GOES HERE"
  private_key_password = "KEY PASS GOES HERE"
  ```

## Use-Case #2: Produce CLI execution examples

Reference `references/cli-clarification.md` about rendering CLI examples.
The reference `references/cxone-sbom-tools-docs.md` has the CLI documentation.

When producing CLI execution examples, check the following before output:

* If this is the first rendered example of the CLI use in the conversation,
  include instructions about how to install `cxone-sbom-tools` with the CLI option.
* If the user's desired example function is ambiguous, prompt for clarification with a
  summary of available functions.


## Use-Case #3: Provide advice about SBOM signatures and verification

Reference `references/signature-verification.md` for summary information
about SBOM signatures and signature verification.  This is not indended to
be comprehensive or authoritative.  Other sources about the signature process
should be recommended to the user if the summary does not provide the
answers to their queries.

## Outputs

Before the initial response to the user is output, you MUST:

  * Remind the user the examples are from the version explained in `references/install.md`
    and that they should check the `cxone-sbom-tools` Github repository for the current release.

