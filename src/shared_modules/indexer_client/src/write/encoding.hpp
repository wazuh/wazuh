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

// Per-operation NDJSON encoding (stage E3a, plan 18 I61; E3c-1 I73 adds the conflict policy and ReplacePreserving). An
// operation is validated and encoded once, in submit (or Group::add), on the producer's thread; its exact wire size is
// what the bucket charges (CA-12) and the bulk carries without re-encoding. Normative contract:
// anexos/e2a-1/contrato-transport.md § Escritura; this header is normative for I73.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "indexer_client/types.hpp"

namespace indexer_client::detail::write
{
    /// The v1 allowlist for index names (indexer_connector/src/indexerConnectorSyncImpl.hpp:72-88).
    bool isSafeIndexName(std::string_view index) noexcept;

    /// Upper bound of ConflictPolicy::retryOnConflict (I73), for the op's policy and the bucket's.
    constexpr std::uint32_t MAX_RETRY_ON_CONFLICT = 100;

    /// Upper bound of Op::tag in bytes (E3c-2 I80). The tag is not part of the wire lines.
    constexpr std::size_t MAX_TAG_SIZE = 256;

    /// The closed scripts of WriteMode::ReplacePreserving (I28, I73). Constant sources: OpenSearch caches a compiled
    /// inline script per source (and rate-limits compilations), so the paths travel in `params.paths`, never in the
    /// source. Exported for the frozen vectors of writeEncoding_test.cpp and for E6's run against a real OpenSearch
    /// (D45). Semantics, in this order:
    ///   1. (versioned only) the version guard of IndexVersionedScript first: an older doc_version ⇒ ctx.op = 'none'
    ///      (noop, no WARN: #40180) and nothing else runs.
    ///   2. Each path of params.paths is looked up in the stored ctx._source walking only through `instanceof Map` and
    ///      `containsKey`: a missing key or a non-Map intermediate means "absent"; the walk never throws.
    ///   3. ctx._source = new HashMap(params.doc): the agent's document replaces the stored one (fields it no longer
    ///      sends disappear); params.doc itself is never mutated.
    ///   4. Every present path is restored: each intermediate map on its way is copied (new HashMap of the existing
    ///      Map, or a new empty one when absent or not a Map) before the put, and the old value wins over the agent's
    ///      at that path (user wins, #37845). An absent path leaves the agent's value (or nothing) in place.
    ///   With scripted_upsert a missing document runs the script on the upsert (the same document): nothing is
    ///   restored that was not already there.
    inline constexpr std::string_view PRESERVE_SOURCE =
        "def kept = []; for (def p : params.paths) { def cur = ctx._source; int last = p.size() - 1; "
        "for (int i = 0; i < last && cur instanceof Map; ++i) { cur = cur.get(p[i]); } "
        "if (cur instanceof Map && cur.containsKey(p[last])) { kept.add([p, cur.get(p[last])]); } } "
        "ctx._source = new HashMap(params.doc); "
        "for (def k : kept) { def p = k[0]; def cur = ctx._source; int last = p.size() - 1; "
        "for (int i = 0; i < last; ++i) { def next = cur.get(p[i]); "
        "next = next instanceof Map ? new HashMap(next) : new HashMap(); cur.put(p[i], next); cur = next; } "
        "cur.put(p[last], k[1]); }";
    inline constexpr std::string_view PRESERVE_VERSIONED_SOURCE =
        "if (ctx._source?.state?.document_version == null || ctx._source.state.document_version <= "
        "params.doc_version) { "
        "def kept = []; for (def p : params.paths) { def cur = ctx._source; int last = p.size() - 1; "
        "for (int i = 0; i < last && cur instanceof Map; ++i) { cur = cur.get(p[i]); } "
        "if (cur instanceof Map && cur.containsKey(p[last])) { kept.add([p, cur.get(p[last])]); } } "
        "ctx._source = new HashMap(params.doc); "
        "for (def k : kept) { def p = k[0]; def cur = ctx._source; int last = p.size() - 1; "
        "for (int i = 0; i < last; ++i) { def next = cur.get(p[i]); "
        "next = next instanceof Map ? new HashMap(next) : new HashMap(); cur.put(p[i], next); cur = next; } "
        "cur.put(p[last], k[1]); } "
        "} else { ctx.op = 'none' }";

    /// Validates `op` (RF-4, I61, I73) against its effective conflict policy (`op.onConflict` when set, else the
    /// bucket's; the caller resolves it) and returns its NDJSON lines, each ending in '\n': the action line and, for
    /// every kind but Delete, the body line. Byte for byte:
    ///   Index                {"index":{"_index":"<i>","_id":"<id>"}}\n<body>\n
    ///   IndexAutoId          {"index":{"_index":"<i>"}}\n<body>\n
    ///   IndexDataStream      {"create":{"_index":"<i>"}}\n<body>\n
    ///   Delete               {"delete":{"_index":"<i>","_id":"<id>"}}\n
    ///   IndexVersionedScript {"update":{"_index":"<i>","_id":"<id>"<R>}}\n{"script":{"source":"<the v1 guard>","lang":
    ///                        "painless","params":{"doc_version":<version>,"doc":<body>}},"upsert":<body>,
    ///                        "scripted_upsert":true}\n   (the v1's shape, ctx.op = 'none')
    ///   Index + ReplacePreserving
    ///                        {"update":{"_index":"<i>","_id":"<id>"<R>}}\n{"script":{"source":"<PRESERVE_SOURCE>",
    ///                        "lang":"painless","params":{"paths":<P>,"doc":<body>}},"upsert":<body>,
    ///                        "scripted_upsert":true}\n
    ///   IndexVersionedScript + ReplacePreserving
    ///                        {"update":{"_index":"<i>","_id":"<id>"<R>}}\n{"script":{"source":
    ///                        "<PRESERVE_VERSIONED_SOURCE>","lang":"painless","params":{"doc_version":<version>,
    ///                        "paths":<P>,"doc":<body>}},"upsert":<body>,"scripted_upsert":true}\n
    /// <R> = ,"retry_on_conflict":<n> only with an effective ConflictPolicy::Retry (update actions only: an index,
    /// create or delete line with it is a 400 for the whole request); with Success the line is today's (v1 parity).
    /// <P> = the preserved paths in the given order, each as an array of its segments: [["case"],["a","b"]] (the
    /// segment alphabet needs no escaping). `_id` is escaped as the v1 escapes it. `op.body` is moved into the result
    /// (one copy of the document; two for the update kinds, which is the wire format, I71); on success `op.body` is
    /// left empty with its memory freed. Failures are Cause::InvalidArgument with the field first in `reason`
    /// ("index: ...", "id: ...", "version: ...", "body: ...", "mode: ...", "onConflict.retryOnConflict: ..."):
    ///   - unsafe or empty index; missing `_id` where required (Index, Delete, IndexVersionedScript) or present
    ///     where the kind has none (IndexAutoId, IndexDataStream); `version` not a canonical integer in
    ///     [0, INT64_MAX] (no leading zero) for IndexVersionedScript or non-empty for any other kind; empty body or a
    ///     '\n' in it for the kinds with a body, a non-empty body for Delete;
    ///   - `tag` (E3c-2 I80) longer than MAX_TAG_SIZE or with a byte below 0x20 or 0x7f ("tag: ...");
    ///   - effective Retry with retryOnConflict 0 or > MAX_RETRY_ON_CONFLICT;
    ///   - ReplacePreserving with a kind other than Index or IndexVersionedScript (I72); preservedPaths with Replace;
    ///     with ReplacePreserving: 0 or more than 16 paths, a path of 0 or more than 8 segments, a segment empty,
    ///     longer than 64 or outside [A-Za-z0-9_@-], two equal paths or one a segment prefix of another, and with
    ///     IndexVersionedScript `state`, `state.document_version` or a path under it (it would defeat the guard).
    /// A per-op Retry on Index/IndexAutoId/IndexDataStream/Delete is accepted and only changes how a 409 item is
    /// treated (futile for `create`: its 409 means "exists"). On failure `op` is untouched.
    Outcome<std::string> encode(Op&& op, const ConflictPolicy& effective);
} // namespace indexer_client::detail::write

#endif // _INDEXER_CLIENT_WRITE_ENCODING_HPP
