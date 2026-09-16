/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * September 10, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_SERVER_CA_CERTIFICATE_SOURCE_HPP
#define _REMOTED_HTTP_SERVER_CA_CERTIFICATE_SOURCE_HPP

/**
 * @file caCertificateSource.hpp
 * @brief The CA file as one coherent thing: the bytes we publish and the verdict about them, taken
 *        from the same read -- and, when that read fails, the last good one we still hold.
 *
 * Before this, `GET /cacerts` opened the file to answer and the certificate monitor opened it again
 * (up to a day earlier) to decide whether it signs the served leaf, so a replaced CA could be handed
 * out with a stale "it matches" behind it, and a repaired one refused for another day. Worse, the
 * answer was the file's own bytes: a PEM that also carried the CA's private key was published whole
 * (issue #39078, H01 and H06).
 *
 * Here one read produces everything: the certificates parsed out of it, a PEM **this process
 * serialised** from those objects (so nothing that is not a certificate can leave), and whether any
 * of them signs the leaf the listener is serving. The result is cached under the SHA-256 of the
 * bytes, not their size or mtime -- a same-size, same-timestamp replacement is exactly the case that
 * has to be caught -- so the common path is one read and one hash, and a changed file is revalidated
 * in the request that notices it.
 *
 * A read that fails does not erase what was being served (issue #39318). A permission change after
 * an upgrade, a non-atomic replacement or an I/O error is a window, not a decision, and the agents
 * that need the CA during that window are exactly the ones a 404 would strand: the snapshot keeps
 * the last good bundle and records the failure (its cause, the errno, how many in a row) so the
 * callers that own a logger can say so. Stopping without a restart is deliberate instead: a readable
 * file that carries no certificate (an emptied one) clears the snapshot at once. The read is bounded
 * for real -- never more than kMaxBytes + 1 bytes are requested, whatever the file's size -- and it is
 * injectable, so every failure path is testable without permission tricks that root ignores. The whole
 * call, read included, runs under the source's mutex, so two readers can never publish out of order.
 */

#include "tlsCertificateStatus.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace remoted::http
{
    /// Outcome of one bounded read of the CA file.
    enum class ReadStatus
    {
        Ok,         ///< `contents` holds the whole file, at most `maxBytes` long.
        CannotOpen, ///< open(2) failed: the file is missing, or not ours to read (ENOENT, EACCES, ...).
        ReadError,  ///< read(2) failed after the open succeeded (EISDIR for a directory, EIO, ...).
        TooLarge    ///< More than `maxBytes` bytes were available; nothing past the cap was requested.
    };

    /// What a FileReader hands back.
    struct ReadResult
    {
        ReadStatus status {ReadStatus::Ok};
        int error {0}; ///< errno of the failed call for CannotOpen and ReadError; 0 otherwise.
    };

    /**
     * @brief Reads @p path into @p contents, requesting at most @p maxBytes + 1 bytes from it.
     *
     * The seam CaCertificateSource reads through. Production uses readFileBounded(); a test passes a
     * reader that fails on demand, or one that records what was asked of it. Must not throw; on
     * anything but Ok, @p contents is left empty.
     */
    using FileReader = std::function<ReadResult(const std::string& path, std::size_t maxBytes, std::string& contents)>;

    /// The default FileReader: POSIX open/read, so the cause of a failure is the exact errno.
    ReadResult readFileBounded(const std::string& path, std::size_t maxBytes, std::string& contents);

    /// The latest read that failed, remembered for as long as the failure lasts.
    struct ReadFailure
    {
        ReadStatus status {ReadStatus::CannotOpen};
        int error {0};                 ///< errno of that read; 0 for TooLarge.
        std::uint64_t consecutive {0}; ///< Failed reads in a row since the last good one: 1 on the first.
    };

    /// Everything `GET /cacerts` and the TLS status need about the CA file, from a single read.
    struct CaCertificateSnapshot
    {
        std::string pem; ///< Certificates only, re-serialised here. Empty when there is nothing to serve.
        std::optional<bool>
            matchesLeaf; ///< Whether some certificate signs the served leaf directly; nullopt when none was read.
        std::optional<bool> chainValid; ///< Whether the leaf validates with the bundle as its trust store (chain,
                                        ///< dates, constraints); nullopt when there is nothing to validate against.
        std::string chainError;         ///< OpenSSL's reason when chainValid is false; empty otherwise.
        std::string subjects;           ///< Comma-separated subjects, for the log lines.
        std::size_t certificates {0};   ///< How many certificates the file yielded.
        /// Present while the latest read failed. The fields above then describe the last GOOD read
        /// (or are empty when there never was one), not the file as it is right now.
        std::optional<ReadFailure> lastReadFailure;
    };

    /**
     * @brief Reader and cache of the CA file behind `remote.https.ca_certificate`.
     *
     * Thread-safe: the endpoint calls snapshot() from the transport's threads, the certificate
     * monitor from its own, the metrics scrape and the legacy task poller from theirs. Every call
     * runs whole under one mutex -- the read too -- so what the last caller published is what the
     * last read saw.
     */
    class CaCertificateSource final
    {
    public:
        /// Largest CA file served. A bundle is a few KB; past this the file is refused as TooLarge,
        /// and never more than kMaxBytes + 1 bytes of it are requested from the reader.
        static constexpr std::size_t kMaxBytes {1024U * 1024U};

        /**
         * @param path Configured CA path; an empty one yields an empty snapshot forever.
         * @param leaf Certificate the listener serves, owned by the caller and outliving this object.
         * @param reader How the bytes are read: readFileBounded() unless a test says otherwise. An
         *               empty function falls back to the default rather than being called.
         */
        CaCertificateSource(std::string path, const X509* leaf, FileReader reader = readFileBounded);

        /**
         * @brief Current state of the file: cached while its content hash is unchanged.
         *
         * When the read fails, the last good snapshot comes back unchanged with `lastReadFailure`
         * set; when it succeeds, `lastReadFailure` is cleared, and identical bytes are still a cache
         * hit even across a failure in between.
         */
        CaCertificateSnapshot snapshot();

        /// How many times the bytes were actually parsed. Only the tests care: it is what proves
        /// the cache holds when the file did not change, and gives way when it did.
        std::uint64_t parses() const;

    private:
        CaCertificateSnapshot buildLocked(std::string_view pem) const;

        const std::string m_path;
        const X509* m_leaf {nullptr};
        const FileReader m_reader;

        mutable std::mutex m_mutex;
        std::string m_hash; ///< SHA-256 of the bytes behind m_snapshot; empty before the first good read.
        CaCertificateSnapshot m_snapshot;
        std::uint64_t m_parses {0};
        std::uint64_t m_consecutiveFailures {0}; ///< Reset by every successful read.
    };
} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_CA_CERTIFICATE_SOURCE_HPP
