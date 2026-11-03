# evtx2xml

A Python tool to convert Windows Event Log (EVTX) files to XML format.

## Installation

From `src/engine/tools/`:

```bash
pip install ./evtx2xml
```

## Usage

Once installed, you can use `evtx2xml` from the command line as follows:

```bash
evtx2xml <evtx_file_path_or_url> > events.xml
```

- `<evtx_file_path_or_url>`: The path to the EVTX file, or an `http`/`https` URL to download it from (saved as
  `tmp_downloaded.evtx` in the current directory and deleted afterwards).

The XML is printed to standard output: an `<Events>` root holding every record. On an invalid path or URL the
tool prints an error and exits with status 1.

## Dependencies

- `evtx` (0.8.2)
- `requests` (2.32.3)

## License

This project is licensed under the AGPLv3 License.

## Contributing

If you would like to contribute to this project, feel free to fork the repo, make your changes, and submit a pull request. All contributions are welcome!

## Contact

If you have any questions or issues, please open an issue on GitHub.

## Links

- [GitHub Repository](https://github.com/wazuh/wazuh)

