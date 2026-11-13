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

// Per-operation NDJSON encoding (including the conflict policy and ReplacePreserving). An
// operation is validated and encoded once, in submit (or Group::add), on the producer's thread; its exact wire size is
// what the bucket charges and the bulk carries without re-encoding. This header is normative.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

#include "indexer_client/types.hpp"

namespace indexer_client::detail::write
{
    /// The v1 allowlist for index names (indexerConnectorSyncImpl.hpp:72-88; the v1 was removed in 5.x).
    bool isSafeIndexName(std::string_view index) noexcept;

    /// Upper bound of ConflictPolicy::retryOnConflict, for the op's policy and the bucket's.
    constexpr std::uint32_t MAX_RETRY_ON_CONFLICT = 100;

    /// Upper bound of Op::tag in bytes. The tag is not part of the wire lines.
    constexpr std::size_t MAX_TAG_SIZE = 256;

    /// The closed scripts of WriteMode::ReplacePreserving. Constant sources: OpenSearch caches a compiled
    /// inline script per source (and rate-limits compilations), so the paths travel in `params.paths`, never in the
    /// source. Exported for the frozen vectors of writeEncoding_test.cpp and for the run against a real OpenSearch.
    /// Semantics, in this order:
    ///   1. (versioned only) the version guard of IndexVersionedScript first: an older doc_version ⇒ ctx.op = 'none'
    ///      (noop, no WARN) and nothing else runs.
    ///   2. Each path of params.paths is looked up in the stored ctx._source walking only through `instanceof Map` and
    ///      `containsKey`: a missing key or a non-Map intermediate means "absent"; the walk never throws.
    ///   3. ctx._source = new HashMap(params.doc): the agent's document replaces the stored one (fields it no longer
    ///      sends disappear); params.doc itself is never mutated.
    ///   4. Every present path is restored: each intermediate map on its way is copied (new HashMap of the existing
    ///      Map, or a new empty one when absent or not a Map) before the put, and the old value wins over the agent's
    ///      at that path (user wins). An absent path leaves the agent's value (or nothing) in place.
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

    /// The action lines of the ops without `_id` (IndexAutoId, IndexDataStream without an id), which depend only on
    /// kind and index, shared by every op of the write path that owns the table (WritePath::heads()). Append-only, at
    /// most CAPACITY entries in fixed slots (a line never moves and is never freed before the table: an op holds a
    /// plain pointer to it, no reference count). A full table refuses new entries and the op builds its own line. The
    /// cap is per runtime lifetime (the table never shrinks): past 256 distinct (kind, index) pairs every op of a new
    /// pair builds its own line, and a full table is seen lock-free (no append mutex, no second scan).
    /// Each table has a process-wide unique, monotonic `generation()`, the key of the per-thread caches (a new table
    /// at the address of a dead one never matches an old entry). Invariant (the owner's): no reader of a line outlives
    /// the table — the runtime joins its pool before it destroys the write path, and a group of a dead path never
    /// reads its ops' lines.
    class HeadTable final
    {
    public:
        static constexpr std::size_t CAPACITY = 256;

        HeadTable();
        HeadTable(const HeadTable&) = delete;
        HeadTable& operator=(const HeadTable&) = delete;

        std::uint64_t generation() const noexcept
        {
            return m_generation;
        }
        /// The line of (kind, index), lock-free over the published slots; null if absent.
        const std::string* find(Op::Kind kind, std::string_view index) const noexcept;
        /// The line of (kind, index): the existing one, or `line` stored now; null when the table is full. A full
        /// table is checked before the append mutex: it never takes it again.
        const std::string* intern(Op::Kind kind, std::string_view index, std::string&& line);
        /// Every entry is taken (lock-free).
        bool full() const noexcept
        {
            return m_count.load(std::memory_order_acquire) == CAPACITY;
        }
        /// Entries stored (tests).
        std::size_t size() const noexcept
        {
            return m_count.load(std::memory_order_acquire);
        }
        /// Takes of the append mutex so far (tests: a full table takes none).
        std::uint64_t appendLocks() const noexcept
        {
            return m_appendLocks.load(std::memory_order_relaxed);
        }

    private:
        struct Slot final
        {
            Op::Kind kind {Op::Kind::IndexAutoId};
            std::string index;
            std::string line;
        };
        const std::uint64_t m_generation;
        std::unique_ptr<Slot[]> m_slots; ///< CAPACITY fixed slots; [0, m_count) published, immutable.
        std::atomic<std::size_t> m_count {0};
        std::mutex m_appendMutex;                     ///< Serializes intern(); readers never take it.
        std::atomic<std::uint64_t> m_appendLocks {0}; ///< Takes of m_appendMutex (written under it).
    };

    /// The wire lines of one op: the action line (and, for the update kinds and Delete, every line) in `head`
    /// or, for IndexAutoId and IndexDataStream without `_id` given a HeadTable, in `cachedHead` (the table's line
    /// shared by every op of that kind and index; `head` then stays empty), and `body` the moved-in document of the
    /// kinds that carry it verbatim (empty otherwise). On the wire the op is headView() + `body` + '\n' (the '\n' only
    /// when `body` is not empty).
    struct Encoded final
    {
        std::string head;
        const std::string* cachedHead {nullptr}; ///< A line of the HeadTable given to encode(), or null.
        std::string body;

        /// The cached head when there is one, else `head`. Every reader of the head goes through it.
        std::string_view headView() const noexcept
        {
            return cachedHead ? std::string_view(*cachedHead) : std::string_view(head);
        }
        std::uint64_t wire() const noexcept;
        /// The bytes charged against the quota: wire() plus the heap slack of `body` (capacity - size when the
        /// body lives on the heap; 0 for an empty or SSO body). `head` is built with an exact reserve; a shared head
        /// counts in wire() of every op that carries it, never apart.
        std::uint64_t charge() const noexcept;
    };

    /// wire() and charge() of a (head, body) pair, shared by Encoded and OpState (`head` is their headView()).
    std::uint64_t wireSize(std::string_view head, const std::string& body) noexcept;
    std::uint64_t chargeSize(std::string_view head, const std::string& body) noexcept;
    /// Appends the wire bytes of a (head, body) pair to `out`.
    void appendWire(std::string& out, std::string_view head, const std::string& body);
    void appendWire(std::string& out, const Encoded& encoded);

    /// Validates `op` against its effective conflict policy (`op.onConflict` when set, else the
    /// bucket's; the caller resolves it) and returns its NDJSON lines, each ending in '\n': the action line and, for
    /// every kind but Delete, the body line. Byte for byte (appendWire of the result):
    ///   Index                {"index":{"_index":"<i>","_id":"<id>"}}\n<body>\n
    ///   IndexAutoId          {"index":{"_index":"<i>"}}\n<body>\n
    ///   IndexDataStream      {"create":{"_index":"<i>"}}\n<body>\n
    ///   IndexDataStream + id {"create":{"_index":"<i>","_id":"<id>"}}\n<body>\n   (never shared, see below)
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
    /// segment alphabet needs no escaping). `_id` is escaped as the v1 escapes it. The result splits those bytes in
    /// two: for Index (Replace) and IndexDataStream with `_id` `head` is the action line with its '\n' (built with an
    /// exact reserve); for IndexAutoId and IndexDataStream without `_id`, given a HeadTable, that line (it depends only
    /// on kind and index) is `cachedHead`, taken from the per-thread cache over the table (see below): on a hit (same
    /// table, kind, index equal byte for byte) neither isSafeIndexName runs nor a line is built; on a miss the index is
    /// validated as always and, once the op is valid, the line is found or interned (an invalid index never enters
    /// the table nor the cache). For those kinds `body` is `op.body`
    /// itself, moved in with its buffer and capacity, never copied nor
    /// re-reserved; for the update kinds and Delete `head` holds every line (the update kinds copy the document twice,
    /// which is their wire format) and `body` is empty. On success `op.body` is left empty (moved from, or its
    /// memory freed for the update kinds); the rest of `op` is not consumed. Failures are Cause::InvalidArgument with
    /// the field first in `reason`
    /// ("index: ...", "id: ...", "version: ...", "body: ...", "mode: ...", "onConflict.retryOnConflict: ..."):
    ///   - unsafe or empty index; missing `_id` where required (Index, Delete, IndexVersionedScript) or present
    ///     where the kind has none (IndexAutoId); for IndexDataStream (optional `_id`) one longer than 512 bytes
    ///     ("id: longer than 512 bytes") or not valid UTF-8 ("id: not valid UTF-8"; that kind only: Index and Delete
    ///     have no bound); `version` not a canonical integer in
    ///     [0, INT64_MAX] (no leading zero) for IndexVersionedScript or non-empty for any other kind; empty body or a
    ///     '\n' in it for the kinds with a body (the '\n' is not searched with `trustedBody`,
    ///     BucketSpec::trustedBodies: the producer guarantees compact JSON and a stray '\n' fails that bulk with 400),
    ///     a non-empty body for Delete;
    ///   - `tag` longer than MAX_TAG_SIZE or with a byte below 0x20 or 0x7f ("tag: ...");
    ///   - effective Retry with retryOnConflict 0 or > MAX_RETRY_ON_CONFLICT;
    ///   - ReplacePreserving with a kind other than Index or IndexVersionedScript; preservedPaths with Replace;
    ///     with ReplacePreserving: 0 or more than 16 paths, a path of 0 or more than 8 segments, a segment empty,
    ///     longer than 64 or outside [A-Za-z0-9_@-], two equal paths or one a segment prefix of another, and with
    ///     IndexVersionedScript `state`, `state.document_version` or a path under it (it would defeat the guard).
    /// A per-op Retry on Index/IndexAutoId/IndexDataStream/Delete is accepted and only changes how a 409 item is
    /// treated (futile for `create`: its 409 means "exists"). One failure is not the caller's:
    /// InvalidState "internal error: ..." when the precomputed size and the encoded lines disagree (a library bug,
    /// logged at ERROR and counted by detail::internalError; the callers count it with the bucket's InvalidArgument
    /// refusals, as the op never entered the bucket). On failure `op` is untouched.
    /// With `heads`, the line of IndexAutoId / IndexDataStream without `_id` comes from that table through a
    /// per-thread cache of THREAD_CACHE entries keyed by (heads->generation(), kind, index) — a hit validates neither
    /// the index nor builds a line; a miss validates as always, then finds or interns the line in the table (a full
    /// table: the op keeps its own `head`) — and `cachedHead` points at it. An IndexDataStream with `_id` never reads
    /// the cache nor the table and never enters them: it always builds its own `head` (`cachedHead` null). Without
    /// `heads` every op builds its own `head`.
    Outcome<Encoded>
    encode(Op&& op, const ConflictPolicy& effective, bool trustedBody = false, HeadTable* heads = nullptr);

    /// Entries of the per-thread cache of encode() (engine workers alternate the raw and the events index,
    /// the latter templated per event).
    constexpr std::size_t THREAD_CACHE = 16;
} // namespace indexer_client::detail::write

#endif // _INDEXER_CLIENT_WRITE_ENCODING_HPP
