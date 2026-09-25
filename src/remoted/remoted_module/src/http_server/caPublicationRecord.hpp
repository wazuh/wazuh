/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * September 18, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_SERVER_CA_PUBLICATION_RECORD_HPP
#define _REMOTED_HTTP_SERVER_CA_PUBLICATION_RECORD_HPP

/**
 * @file caPublicationRecord.hpp
 * @brief The node's private memory of the CA bundle it last served: which bytes, and under which
 *        publication. Persistence and nothing else -- it does not log and it does not decide.
 *
 * Why a record at all (issue #39319): an ordinary CA file carries no publication block, and so does
 * a published bundle somebody rewrote by hand. Without memory those two look identical, so remoted
 * could not tell "this node was never stamped" (an INFO with the command that fixes it) from "the
 * bundle that WAS published generation N is not published any more" (a WARN naming N). The record
 * is that memory, and it is auxiliary by construction: serving `GET /cacerts` and vouching for the
 * bundle never read it, so a record that cannot be written costs one log line, never a rotation
 * (C19).
 *
 * It lives in a directory of its own (`var/run/remoted-ca-bundle/`, mode 0750, created by remoted
 * at start -- see ensureRecordDirectory()): a directory nobody else writes to is what lets a write
 * failure be injected for a test without touching `var/run` itself, where the pidfiles of every
 * other daemon live (C24, C25). Its owner is the service's own user, not root.
 *
 * Two hard rules:
 *   - the record NEVER points at the bundle. If its path resolves to the bundle's (a symlink, a
 *     configuration mistake), load() and store() refuse without writing a byte: the one file this
 *     feature must never modify is the bundle (RF-8, CA-19), and a fail-closed refusal is the only
 *     way to be sure (C23).
 *   - a record that does not describe THIS bundle, or that cannot be read or parsed, is an absence.
 *     It never lends its publication to another file. The caller is told which of those it was,
 *     because "unreadable" must not be reported to an operator as "never published" (C23).
 *
 * The write is the ordinary atomic-replace dance, in this order: a unique temporary (O_EXCL, 0600)
 * -> the whole entry written (short writes and EINTR handled) -> fsync -> fchmod 0640 -> rename ->
 * fsync of the DIRECTORY. The last one is what makes the rename survive a power loss; if only it
 * fails, the record on disk is already correct, so store() reports success and leaves the cause in
 * lastError() for the caller to warn about uncertain durability.
 */

#include "fileRead.hpp" // FileReader, readFileBounded

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <sys/types.h>

namespace remoted::http
{
    /// What the record remembers about one bundle: the bytes it saw and the publication they were
    /// announced under. `bundlePath` is what makes the entry non-transferable to another file.
    struct Entry
    {
        std::string bundlePath;       ///< The bundle this publication belongs to, as configured.
        std::string fileSha256;       ///< SHA-256 of that bundle's bytes when the entry was written.
        std::int64_t publication {0}; ///< The publication in effect for those bytes; 0 means unpublished.
    };

    /// What load() found. Anything but `ok` is treated as an absence by the caller -- but WHICH of
    /// them it was decides whether an operator hears "never published" or "I cannot read my record".
    struct LoadOutcome
    {
        Entry entry; ///< Meaningful only when `status == ok`; default-constructed otherwise.

        enum class Status
        {
            ok,          ///< Read, parsed, and it describes the bundle asked about.
            absent,      ///< No record yet: a fresh node, or the first start after an upgrade.
            unreadable,  ///< It is there and could not be read (permissions, I/O, a directory).
            malformed,   ///< Read, but it is not a record: bad JSON, wrong types, or over kMaxBytes.
            foreign_path ///< It describes another bundle, or its own path resolves to the bundle.
        };

        Status status {Status::absent};
        /// errno for `unreadable`; EINVAL for the `foreign_path` case where the record's path IS
        /// the bundle (the fail-closed refusal, as opposed to a record about another file); 0
        /// otherwise.
        int error {0};
    };

    /**
     * @brief The syscalls store() makes, injectable.
     *
     * Not for production (every field empty means "call the real one"), but there is no other way
     * to test a short write, a write that fails halfway or a directory whose fsync is refused:
     * these tests run as root in CI, and root ignores the permissions that would produce them.
     * Deliberately narrow -- the three seams the failure paths need, not a filesystem abstraction.
     */
    struct RecordIo
    {
        /// How load() reads the record; readFileBounded() unless a test says otherwise.
        FileReader read {};
        /// One write(2) on an open fd. A test returns a short count, -1 with an errno, or sleeps.
        std::function<ssize_t(int fd, const void* data, std::size_t bytes)> write {};
        /// One fsync(2). @p directory tells the temporary's flush from the directory's, so a test
        /// can refuse exactly the second one.
        std::function<int(int fd, bool directory)> sync {};
    };

    /**
     * @brief Loads and stores the publication record at a fixed path.
     *
     * Not thread-safe for concurrent store() calls by design: exactly one writer runs at a time,
     * and the caller (CaCertificateSource::flushPendingRecord()) enforces it with a try_lock, so
     * the write never queues behind another. Concurrent load() and lastError() are fine.
     */
    class CaPublicationRecord final
    {
    public:
        /// Largest record accepted. An entry is ~200 bytes; past this the file is not a record we
        /// wrote, so it is refused as malformed instead of parsed (C23).
        static constexpr std::size_t kMaxBytes {4096};

        /// Version stamped into the document, so a future shape can be told apart rather than
        /// half-read. A record carrying anything else is malformed.
        static constexpr int kVersion {1};

        /**
         * @param path Where the record lives; relative paths resolve against remoted's cwd (the
         *             chroot root), like every other path in HttpServerConfig.
         * @param io   Test seams for the write path; every empty field means the real syscall.
         */
        explicit CaPublicationRecord(std::string path, RecordIo io = {});

        /**
         * @brief The entry for @p bundlePath, or why there is none. Never throws, never writes.
         *
         * `ok` requires the document to parse, to carry this version, and to name @p bundlePath
         * (compared after resolving both through realpath(3), so a symlinked bundle still matches
         * itself). Anything else is one of the other four statuses.
         */
        LoadOutcome load(const std::string& bundlePath) const;

        /**
         * @brief Replaces the record with @p entry, atomically.
         *
         * @return true when the entry is on the path -- including the case where the directory
         *         could not be flushed afterwards, which leaves lastError() non-zero: the record is
         *         correct, only its durability across a power loss is uncertain. false means
         *         nothing was written and the previous record (if any) is untouched.
         */
        bool store(const Entry& entry);

        /// Cause of the last store(): 0 after a fully durable one, the errno of the call that
        /// refused otherwise. load() reports through LoadOutcome::error instead and never moves it.
        int lastError() const noexcept;

        /// Where this record lives -- what the "cannot persist" line has to name.
        const std::string& path() const noexcept;

    private:
        /// Whether @p bundlePath and the record's own path are the same file. The fail-closed check
        /// both load() and store() run first (C23).
        bool aliases(const std::string& bundlePath) const;

        const std::string m_path;
        const RecordIo m_io;
        /// Distinguishes the temporaries of two stores (in this process, and from another process's)
        /// so O_EXCL never refuses a write because of a leftover name.
        std::atomic<std::uint64_t> m_attempt {0};
        std::atomic<int> m_lastError {0};
    };

    /**
     * @brief Creates the record's own directory (mode 0750) if it is not there yet.
     *
     * Called by remoted at start, once, before the record is used: the directory is part of the
     * runtime tree (`var/run/`, which the service owns), not of the package, so nothing in the
     * installer has to know about it (RNF-4, C25). Best-effort by design -- when it cannot be
     * created, the first store() fails with the real errno and the operator gets that line, which
     * is more informative than anything that could be said here.
     *
     * Not recursive on purpose: it creates the record's own directory inside an existing `var/run`,
     * and never a tree of directories somewhere a misconfigured path points at.
     *
     * @return true when the directory exists afterwards.
     */
    bool ensureRecordDirectory(const std::string& recordPath);
} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_CA_PUBLICATION_RECORD_HPP
