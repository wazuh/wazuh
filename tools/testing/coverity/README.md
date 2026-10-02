# Coverity scan tool

This directory contains a helper script and a Dockerfile for running [Coverity static analysis](https://scan.coverity.com/) on the Wazuh codebase. It allows executing the analysis both locally and in CI environments using the same containerized setup.

## Files

- `coverity.sh`: main helper script for downloading the image, running the analysis, and uploading results.
- `Dockerfile`: defines the image used to compile Wazuh with Coverity analysis enabled.

## Usage

```bash
./coverity.sh [--build-image] [--build] [--upload] [--clean] [--jobs N] [--tag <tag>]
```

If run without arguments, the script will **compile** the project with Coverity and **upload** the results.

The analysis builds the manager (`make -C src TARGET=manager COVERITY=YES`) inside the image, whose entrypoint is `cov-build --dir cov-int`. It does not fetch the external dependencies: run `make -C src deps TARGET=manager` once before the first `--build`.

### Options

* `--build-image`
  Download the Coverity analysis tool and build the Docker image.
  The script exits immediately after this step.
  **Requires** `COVERITY_TOKEN` to be set.

* `--build`
  Run `make clean-internals` and `make clean-windows`, compile the manager using the Coverity Docker image, and pack the output in `wazuh.tgz`.
* `--upload`
  Upload `wazuh.tgz` to Coverity Scan.
  **Requires** `COVERITY_TOKEN` to be set.
  Fails if the tarball does not exist.
* `--clean`
  Remove generated files (`cov-int/` directory and `wazuh.tgz` tarball).
* `--jobs N`
  Set the number of parallel jobs used during compilation (default: system `nproc`).
* `--tag <tag>`
  Tag of the analysis image, `ghcr.io/wazuh/coverity-scan:<tag>` (default: `latest`).
* `--help`
  Show usage information.

### Environment variables

* `PROJECT`
  Coverity project name, used as `wazuh/<PROJECT>` (the script does not validate it).
  Default: `wazuh`.
* `COVERITY_TOKEN`
  Coverity project token.
  Required for `--build-image` and `--upload`.
* `EMAIL`
  Email address associated with the Coverity account.
  Default: `devel@wazuh.com`.

### Build output

* The analysis results are generated in the `cov-int` directory under the project root.
* A compressed tarball `wazuh.tgz` is created in the project root and uploaded to Coverity.

### Version and description

The uploaded analysis includes metadata extracted from the project:

* `VERSION` is taken from `VERSION.json` using `.version + "-" + .stage`.
* `DESCRIPTION` is set to: `Version $VERSION - Git ref <ref>`, where `<ref>` is the exact tag of `HEAD`, or the branch name when there is none.

## Example: full workflow

```bash
# Build image (only needed once or when dependencies change)
COVERITY_TOKEN=your_token ./coverity.sh --build-image

# Run analysis and upload result
COVERITY_TOKEN=your_token ./coverity.sh

# Just upload the build to the ossec-wazuh project
COVERITY_TOKEN=your_token PROJECT=ossec-wazuh ./coverity.sh --upload

# Clean generated files after analysis
./coverity.sh --clean
```

## Notes

You can run this same scan from GitHub Actions, in the `5_codeanalysis_coverity.yml` workflow; `5_codeanalysis_coverity-image.yml` builds the image.
