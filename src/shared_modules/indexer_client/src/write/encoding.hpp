/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _INDEXER_CLIENT_WRITE_ENCODING_HPP
#define _INDEXER_CLIENT_WRITE_ENCODING_HPP

// Per-operation NDJSON encoding (stage E3a, plan 18 I61). An operation is validated and encoded once, in submit, on the
// producer's thread; its exact wire size is what the bucket charges (CA-12) and the bulk (E3b) carries without
// re-encoding. Normative contract: anexos/e2a-1/contrato-transport.md § Escritura.

#include <string>
#include <string_view>

#include "indexer_client/types.hpp"

namespace indexer_client::detail::write
{
    /// The v1 allowlist for index names (indexer_connector/src/indexerConnectorSyncImpl.hpp:72-88).
    bool isSafeIndexName(std::string_view index) noexcept;

    /// Validates `op` (RF-4, I61) and returns its NDJSON lines, each ending in '\n': the action line and, for every
    /// kind but Delete, the body line. Byte-for-byte the v1's shapes:
    ///   Index                {"index":{"_index":"<i>","_id":"<id>"}}\n<body>\n
    ///   IndexAutoId          {"index":{"_index":"<i>"}}\n<body>\n
    ///   IndexDataStream      {"create":{"_index":"<i>"}}\n<body>\n
    ///   Delete               {"delete":{"_index":"<i>","_id":"<id>"}}\n
    ///   IndexVersionedScript {"update":{"_index":"<i>","_id":"<id>"}}\n{"script":{...ctx.op = 'none'...,"params":
    ///                        {"doc_version":<version>,"doc":<body>}},"upsert":<body>,"scripted_upsert":true}\n
    /// `_id` is escaped as the v1 escapes it. `op.body` is moved into the result (one copy of the document; two for
    /// IndexVersionedScript, which is the wire format); on success `op.body` is left empty with its memory freed.
    /// Failures are Cause::InvalidArgument with the field first in `reason` ("index: ...", "id: ...", "version: ...",
    /// "body: ...", "mode: ..."): unsafe or empty index; missing `_id` where required (Index, Delete,
    /// IndexVersionedScript) or present where the kind has none (IndexAutoId, IndexDataStream); `version` not
    /// a canonical integer in [0, INT64_MAX] (no leading zero) for IndexVersionedScript or non-empty for any other
    /// kind; empty body or a '\n' in it for the kinds with a body, a non-empty body for Delete; WriteMode
    /// ReplacePreserving (E3c). On failure `op` is untouched.
    Outcome<std::string> encode(Op&& op);
} // namespace indexer_client::detail::write

#endif // _INDEXER_CLIENT_WRITE_ENCODING_HPP
