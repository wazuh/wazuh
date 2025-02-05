# Wazuh Server Technical Documentation

This folder contains the technical documentation for the Wazuh Server. The documentation is organized into the following guides:

- Development Guide: Instructions for building, testing, and packaging the server.
- Reference Manual: Detailed information on the server’s architecture, configuration, and usage.
- Diagnostic Guide: Steps to diagnose errors and resolve common issues.
- Packages Guide: Steps for generating, installing, upgrading, and uninstalling packages.

## Requirements

To work with this documentation, you need **mdBook** installed. For installation instructions, refer to the [mdBook documentation](https://rust-lang.github.io/mdBook/).

## Usage

- To build the documentation, run:
  ```bash
  ./build.sh
  ```
  The output will be generated in the `book` directory.

- To serve the documentation locally for preview, run:
  ```bash
  ./server.sh
  ```
  The documentation will be available at [http://127.0.0.1:3000](http://127.0.0.1:3000).