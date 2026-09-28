# Documentation Installation Guide

This guide explains how to set up and build the Wazuh technical documentation locally.

## Prerequisites

### Required Tool Versions

The following specific versions are required for compatibility with the global documentation build system:

| Tool | Required Version |
|------|-----------------|
| `mdbook` | `0.4.40` |
| `mdbook-mermaid` | `0.13.0` |

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
manager configuration reference, then builds the book. This is also what CI runs.

```bash
cd docs
./build.sh
```

The output will be generated in the `docs/book` directory.

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
2. Check that `mermaid.min.js` and `mermaid-init.js` are present in the `docs/js/` directory
3. Ensure the `book.toml` preprocessor configuration is correct

### Build Errors

If you encounter parse errors in `book.toml`, ensure:

- No unsupported fields like `multilingual = false` are present
- The configuration matches the standardized format
- All required sections are present

## Additional Resources

- [mdBook Documentation](https://rust-lang.github.io/mdBook/)
- [mdbook-mermaid Documentation](https://github.com/badboy/mdbook-mermaid)
- [Wazuh Repository](https://github.com/wazuh/wazuh)
