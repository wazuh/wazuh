# Origin of the license texts in this directory

This file documents where each text comes from. It is not a license text and
`generate.py` never includes it in the generated notices.

| File | Origin |
|---|---|
| `GPL-3.0.txt` | Verbatim copy of `/usr/share/common-licenses/GPL-3` (Debian `base-files`), 674 lines. |
| `GCC-exception-3.1.txt` | Lines 241-312 of `/usr/share/doc/libstdc++6/copyright` (GCC Runtime Library Exception, version 3.1). |
| `nlohmann-MIT.txt` | MIT license text with the copyright line from the SPDX header of `src/external/nlohmann/json.hpp` (lines 6-7: 2013-2022 Niels Lohmann). |
| `sqlite-blessing.txt` | The public-domain dedication and blessing from the header of `src/external/sqlite/sqlite3.c` (from line 35). |
| `pypi-opensearch_protobufs.txt` | Canonical Apache License 2.0 text (same text as `src/external/flatbuffers/LICENSE`), lines 4-204, preceded by a one-line note; the wheel ships no license file. |
| `pypi-flatbuffers.txt` | Same as the previous file, with the note naming flatbuffers (copyright Google Inc.); the wheel ships no license file. |
| `pypi-defusedxml.txt` | Reconstructed: the distribution ships no license file; pending legal review. Lines 1-2 are a note, lines 4-52 the Python Software Foundation License version 2 text copied from CPython's `LICENSE.txt`, not defusedxml's own file. |
| `pypi-content_size_limit_asgi.txt` | Reconstructed: the distribution ships no license file; pending legal review. Generic MIT text whose copyright holder was inferred from the `Author` field of the wheel METADATA. |

The `pypi-*` files are referenced from `python_overrides` in `../components.json`.
