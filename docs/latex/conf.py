from cxone_sbom import __version__

# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "cxone-sbom-tools"
copyright = "2026, Checkmarx"
author = "Nathan Leach, OSCP, CSSLP, Staff Solutions Architect"
release = __version__

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = ["autoapi.extension"]

autoapi_dirs = ["src/cxone_sbom"]
autoapi_member_order = "alphabetical"
autoapi_options = ["members", "inherited-members", "undoc-members", "show-inheritance"]
autoapi_ignore = [
    "*exceptions*",
    "cxone_sbom/__version__.py",
]
autoapi_python_class_content = "both"
maximum_signature_line_length = 60

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

language = "en"

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "alabaster"
html_static_path = ["_static"]


latex_elements = {"makeindex": r"\usepackage[columns=1]{idxlayout}\makeindex"}
