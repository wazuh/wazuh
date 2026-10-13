# Documentation Installation Guide

This guide explains how to set up and build the Wazuh technical documentation locally.

## Prerequisites

### Required Tool Versions

The following specific versions are required for compatibility with the global documentation build system:

| Tool | Required Version |
|------|-----------------|
| `mdbook` | `0.4.40` |
| `mdbook-mermaid` | `0.13.0` |
| Python 3 with `PyYAML` | `PyYAML` `6.0.3` in CI |
| Node.js and `npm` (optional — only needed for Mermaid diagram validation) | Node.js `20` in CI |

`build.sh` runs two Python tools (`docs/tools/gen-manager-conf-ref.py` and `docs/tools/check-docs.py`, which
imports `yaml`), and `check-docs.py` validates the Mermaid diagrams with Node.js: on its first run it
installs the pinned `jsdom` from `docs/tools/package-lock.json` with `npm ci` into
`~/.cache/wazuh-docs-tools` (or `$WAZUH_DOCS_NODE_DIR`), outside `docs/` so that mdBook does not
publish it. These versions are the ones the CI job (`.github/workflows/5_testbuild_docs.yml`) installs.
Node.js and `npm` are not a hard requirement, though: if `node` is not on `PATH`, or if `npm` is not on
`PATH` and the `jsdom` cache needs to be (re)built, `check-docs.py` detects it, prints
`check-docs: node not found on PATH, skipping Mermaid validation` or
`check-docs: npm not found on PATH, skipping Mermaid validation` respectively, and continues without
validating the Mermaid diagrams — the rest of the script's checks already ran and their findings can
still fail the build.

## Installation

### Installing mdBook

#### Using Cargo (Rust Package Manager)

```bash
# Install mdbook 0.4.40
cargo install mdbook --version 0.4.40

# Install mdbook-mermaid 0.13.0
cargo install mdbook-mermaid --version 0.13.0
```

#### Using Pre-built Binaries

Download the appropriate binaries for your platform:

- **mdbook 0.4.40**: https://github.com/rust-lang/mdBook/releases/tag/v0.4.40
- **mdbook-mermaid 0.13.0**: https://github.com/badboy/mdbook-mermaid/releases/tag/v0.13.0

### Verification

After installation, verify the versions:

```bash
mdbook --version
# Expected output: mdbook v0.4.40

mdbook-mermaid --version
# Expected output: mdbook-mermaid 0.13.0
```

## Building the Documentation

### Local Development Server

To serve the documentation locally with live reload:

```bash
cd docs
mdbook serve
```

The documentation will be available at `http://127.0.0.1:3000`

### Building Static HTML

To build the documentation as static HTML, use `docs/build.sh` rather than calling `mdbook build`
directly: it first runs `tools/gen-manager-conf-ref.py --check` to refuse a build with a stale
manager configuration reference, then builds the book, and finally runs `docs/tools/check-docs.py`, which
fails on any broken link or anchor, unpublished page, invalid example block or unparsable diagram
(`python3 tools/check-docs.py --list-checks` lists every check). This is also what CI runs, from the
`docs/` directory:

```bash
cd docs
sh build.sh
```

The output will be generated in the `docs/book` directory. `mdbook serve` skips both checks, so run
`build.sh` before opening a pull request.

## Troubleshooting

### Version Mismatch

If you encounter build errors, ensure you have the exact versions specified above:

```bash
# Check your installed versions
mdbook --version
mdbook-mermaid --version
```

### Mermaid Diagrams Not Rendering

If Mermaid diagrams are not rendering:

1. Verify `mdbook-mermaid` is installed correctly
2. Check that `mermaid.min.js` and `mermaid-init.js` are present in the `docs/` directory, which
   `book.toml` loads through `additional-js`
3. Ensure the `[preprocessor.mermaid]` section of `book.toml` is present

## Additional Resources

- [mdBook Documentation](https://rust-lang.github.io/mdBook/)
- [mdbook-mermaid Documentation](https://github.com/badboy/mdbook-mermaid)
- [Wazuh Repository](https://github.com/wazuh/wazuh)
