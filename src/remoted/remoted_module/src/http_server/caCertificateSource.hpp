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
 *        from the same read.
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
 */

#include "tlsCertificateStatus.hpp"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace remoted::http
{
    /// Everything `GET /cacerts` and the TLS status need about the CA file, from a single read.
    struct CaCertificateSnapshot
    {
        std::string pem; ///< Certificates only, re-serialised here. Empty when there is nothing to serve.
        std::optional<bool>
            matchesLeaf;              ///< Whether some certificate signs the served leaf; nullopt when none was read.
        std::string subjects;         ///< Comma-separated subjects, for the log lines.
        std::size_t certificates {0}; ///< How many certificates the file yielded.
    };

    /**
     * @brief Reader and cache of the CA file behind `remote.https.ca_certificate`.
     *
     * Thread-safe: the endpoint calls snapshot() from the transport's threads and the certificate
     * monitor from its own.
     */
    class CaCertificateSource final
    {
    public:
        /// Largest CA file read. A bundle is a few KB; past this the file is treated as unreadable
        /// rather than pulled into memory once per request.
        static constexpr std::size_t kMaxBytes {1024U * 1024U};

        /**
         * @param path Configured CA path; an empty one yields an empty snapshot forever.
         * @param leaf Certificate the listener serves, owned by the caller and outliving this object.
         */
        CaCertificateSource(std::string path, const X509* leaf);

        /// Current state of the file: cached while its content hash is unchanged.
        CaCertificateSnapshot snapshot();

        /// How many times the bytes were actually parsed. Only the tests care: it is what proves
        /// the cache holds when the file did not change, and gives way when it did.
        std::uint64_t parses() const;

    private:
        CaCertificateSnapshot buildLocked(std::string_view pem) const;

        const std::string m_path;
        const X509* m_leaf {nullptr};

        mutable std::mutex m_mutex;
        std::string m_hash; ///< SHA-256 of the bytes behind m_snapshot; empty before the first read.
        CaCertificateSnapshot m_snapshot;
        std::uint64_t m_parses {0};
    };
} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_CA_CERTIFICATE_SOURCE_HPP
