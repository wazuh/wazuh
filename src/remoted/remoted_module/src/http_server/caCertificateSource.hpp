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
 * an upgrade, a file moved away or an I/O error is a window, not a decision, and the agents that
 * need the CA during that window are exactly the ones a 404 would strand: the snapshot keeps the
 * last good bundle and records the failure (its cause, the errno, how many in a row) so the
 * callers that own a logger can say so. Stopping without a restart is deliberate instead: a readable
 * file that carries no certificate (an emptied one) clears the snapshot at once -- which is also why
 * the file must be REPLACED atomically (write a sibling, rename it over the path): a file caught
 * half-written is readable, and reads as emptied or as refused whole. The read is bounded
 * for real -- never more than kMaxBytes + 1 bytes are requested, whatever the file's size -- and it is
 * injectable, so every failure path is testable without permission tricks that root ignores. The whole
 * call, read included, runs under the source's mutex, so two readers can never publish out of order.
 */

#include "certificateDescriptor.hpp"
#include "fileRead.hpp"
#include "tlsCertificateStatus.hpp"

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace remoted::http
{
    /// One certificate of the bundle as `GET /tls` reports it.
    struct CaCertificateEntry
    {
        CertificateDescriptor certificate;
        bool signsLeaf {false}; ///< caSignsLeaf() against the served leaf: a direct signature check, not a
                                ///< chain verdict. False when there was no leaf to check against.
    };

    /// Everything `GET /cacerts`, the TLS status and `GET /tls` need about the CA file, from a single read.
    struct CaCertificateSnapshot
    {
        std::string pem; ///< Certificates only, re-serialised here. Empty when there is nothing to serve.
        std::size_t serializedBytes {0};         ///< pem.size(): what an agent receives, against kAgentBodyLimit.
        std::vector<CaCertificateEntry> entries; ///< One per certificate, in file order.
        std::string contentSha256; ///< contentSha256() of the certificates read; empty when there is none.
        /// The `##` publication block of the bundle (#39319): the timestamp `wazuh-manager-certs`
        /// stamped and whether its hash vouched for these bytes. 0 / false until that parser exists,
        /// and when the block is missing or does not match.
        std::uint64_t publication {0};
        bool publicationVouched {false};
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
        /// The instant the chain verdict is evaluated at. Empty means OpenSSL's own clock (production).
        using Clock = std::function<std::time_t()>;

        /// Largest CA file served. A bundle is a few KB; past this the file is refused as TooLarge,
        /// and never more than kMaxBytes + 1 bytes of it are requested from the reader.
        static constexpr std::size_t kMaxBytes {1024U * 1024U};

        /// What a bundle may hold and still reach every agent (spike #39277, D5; #39319 § 3): at most
        /// this many certificates, serialised into at most kAgentBodyLimit bytes -- the agent's
        /// HC_MAX_CACERTS_BODY (8192) less its terminator -- whichever binds first. Neither is enforced
        /// here (the file is the operator's); `GET /tls` reports both next to the current values so the
        /// room left is visible, and the rotation tool refuses to publish past them.
        static constexpr std::size_t kMaxCertificates {6};
        static constexpr std::size_t kAgentBodyLimit {8191};

        /**
         * @param path Configured CA path; an empty one yields an empty snapshot forever.
         * @param leaf Certificate the listener serves. The source takes its own reference (X509_up_ref),
         *             so a later start() replacing the listener's leaf cannot free it under a caller
         *             that still holds this source (the metrics scrape, the legacy poller).
         * @param reader How the bytes are read: readFileBounded() unless a test says otherwise. An
         *               empty function falls back to the default rather than being called.
         * @param clock  What the chain verdict is evaluated against; empty for the current time.
         */
        CaCertificateSource(std::string path, const X509* leaf, FileReader reader = readFileBounded, Clock clock = {});

        /**
         * @brief Current state of the file: cached while its content hash is unchanged.
         *
         * When the read fails, the last good snapshot comes back unchanged with `lastReadFailure`
         * set; when it succeeds, `lastReadFailure` is cleared, and identical bytes are still a cache
         * hit even across a failure in between.
         *
         * The chain verdict (`chainValid`/`chainError`) is the one thing the cache does not hold: it has
         * a date term, so it is re-evaluated against the clock on every call -- hit, miss or failed
         * read -- for the certificates of the snapshot being returned.
         */
        CaCertificateSnapshot snapshot();

        /// How many times the bytes were actually parsed. Only the tests care: it is what proves
        /// the cache holds when the file did not change, and gives way when it did.
        std::uint64_t parses() const;

    private:
        /// Everything about @p certificates except the chain verdict, which validateChainLocked() owns.
        CaCertificateSnapshot buildLocked(const std::vector<X509Ptr>& certificates) const;
        /// chainValid/chainError of m_snapshot from m_leaf and m_certificates, as of m_clock (or now).
        void validateChainLocked();

        const std::string m_path;
        X509Ptr m_leaf; ///< Our own reference to the served leaf; null when the caller passed none.
        const FileReader m_reader;
        const Clock m_clock;

        mutable std::mutex m_mutex;
        std::string m_hash; ///< SHA-256 of the bytes behind m_snapshot; empty before the first good read.
        CaCertificateSnapshot m_snapshot;
        std::vector<X509Ptr> m_certificates; ///< The parsed certificates behind m_snapshot, kept for the verdict.
        std::uint64_t m_parses {0};
        std::uint64_t m_consecutiveFailures {0}; ///< Reset by every successful read.
    };

    /**
     * @brief The TLS status a CA snapshot implies for @p leaf: expiry from the leaf, everything
     *        about the CA -- verdicts, subjects, chain, the last read failure -- from @p ca.
     *
     * The one way the transport builds its status, at start and on every monitor tick, so the two
     * can never describe the same file differently. `evaluations` is left at 0: counting is the
     * monitor's job. Pure, so the tests drive it from certificates built in memory.
     */
    TlsCertificateSnapshot statusFrom(const X509* leaf, const CaCertificateSnapshot& ca);
} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_CA_CERTIFICATE_SOURCE_HPP
