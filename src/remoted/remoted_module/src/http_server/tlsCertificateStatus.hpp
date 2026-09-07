/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * September 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_SERVER_TLS_CERTIFICATE_STATUS_HPP
#define _REMOTED_HTTP_SERVER_TLS_CERTIFICATE_STATUS_HPP

/**
 * @file tlsCertificateStatus.hpp
 * @brief Health of the listener's TLS certificate: days until expiry and whether the configured CA
 *        (`remote.https.ca_certificate`, the one `GET /cacerts` hands out) actually signs it.
 *
 * Split out of RestinioHttpServer.cpp for the same reason certificateMatchesPeerIp() was: the
 * decisions are pure functions of an X509 and a file, so they are unit-testable from certificates
 * built in memory, with no socket, handshake or RESTinio involved. The evaluation RETURNS its
 * result; the transport (which owns the logger) turns it into ERROR/WARN lines -- keeping
 * loggerHelper.h out of this header, as common/logThrottle.hpp explains.
 *
 * Only <openssl/types.h> is pulled in here (X509 stays an incomplete type), so IHttpServer.hpp
 * can carry TlsCertificateSnapshot without leaking the OpenSSL API into every endpoint.
 */

#include <openssl/types.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace remoted::http
{
    /// Deleter kept out of line so X509 can stay incomplete for the header's includers.
    struct X509Deleter
    {
        void operator()(X509* certificate) const noexcept;
    };

    /// Owning X509 handle.
    using X509Ptr = std::unique_ptr<X509, X509Deleter>;

    /**
     * @brief Read every CERTIFICATE block of a PEM file.
     *
     * Non-certificate blocks (a key, a CRL) are skipped by OpenSSL's PEM reader, so a bundle or
     * a combined file works. Empty when the file is missing, unreadable or carries no certificate:
     * the caller cannot tell those apart, and does not need to -- none of them can be served.
     */
    std::vector<X509Ptr> loadCertificates(const std::string& pemPath);

    /**
     * @brief Whole days until @p certificate's notAfter, negative once expired.
     *
     * Truncated toward zero, except that an already-expired certificate never reads 0: the first
     * 24 h past notAfter read -1, so "negative" is a strict synonym of "expired". nullopt for a
     * null certificate or one whose notAfter cannot be compared.
     */
    std::optional<int> daysUntilExpiry(const X509* certificate);

    /**
     * @brief Whether any of @p cas signed @p leaf (`X509_verify` against each CA's public key).
     *
     * A signature check, not a chain validation: no dates, no name constraints, no basicConstraints.
     * That is deliberate -- the question `GET /cacerts` needs answered is "would the PEM I am about
     * to hand out let an agent trust the certificate I am serving", and the issuer signature is the
     * one property that decides it. A self-signed leaf listed as its own CA matches.
     */
    bool anyCaSignsLeaf(const X509* leaf, const std::vector<X509Ptr>& cas);

    /**
     * @brief Point-in-time result of one certificate evaluation.
     *
     * Published two ways: by the facade as the `remoted.server.tls.*` pull metrics, and to
     * `GET /cacerts`, which refuses (503) to hand out a CA that does not sign the served leaf.
     * The default-constructed value is what a server that never started reports.
     */
    struct TlsCertificateSnapshot
    {
        std::optional<int> expiryDays;     ///< Days until the served leaf expires; see daysUntilExpiry().
        std::optional<bool> caMatchesLeaf; ///< true/false when the CA file was readable and carried at
                                           ///< least one certificate; nullopt when it was not (a
                                           ///< missing CA is "unknown", never "mismatch").
        std::uint64_t evaluations {0};     ///< How many evaluations produced snapshots so far (1 after
                                           ///< the start-time one; +1 per monitor tick).
        std::string leafSubject;           ///< Subject of the served leaf, for the log lines.
        std::string caSubjects;            ///< Subjects of the certificates read from the CA file,
                                           ///< comma-separated; empty when none was readable.
    };

    /**
     * @brief Evaluate @p leaf against the CA file at @p caPath, re-reading the file now.
     *
     * The leaf is the one loaded into the SSL_CTX (constant until the listener restarts); the CA is
     * whatever is on disk at this moment, so a rotated CA is noticed at the next evaluation. The
     * returned `evaluations` is 0 -- counting is the monitor's job.
     */
    TlsCertificateSnapshot evaluateCertificateStatus(const X509* leaf, const std::string& caPath);

    /**
     * @brief Periodic re-evaluation on its own thread, plus the latest snapshot.
     *
     * The module's canonical shape for a recurring task (Keystore's watcher, the merged.mg watcher):
     * a thread parked on a condition_variable's wait_for, so stop() wakes it immediately instead
     * of waiting out the interval. Not an io_context timer on purpose -- RESTinio's run_async()
     * owns its io_context privately (D45).
     *
     * record() lets the caller store the start-time evaluation BEFORE the thread exists, so the
     * status is already valid when the listener starts accepting. stop() is idempotent and joins;
     * the destructor calls it.
     */
    class TlsCertificateMonitor final
    {
    public:
        using EvaluateFn = std::function<TlsCertificateSnapshot()>;

        TlsCertificateMonitor() = default;
        ~TlsCertificateMonitor();

        TlsCertificateMonitor(const TlsCertificateMonitor&) = delete;
        TlsCertificateMonitor& operator=(const TlsCertificateMonitor&) = delete;

        /// Store a completed evaluation as the current snapshot (bumps `evaluations`).
        void record(TlsCertificateSnapshot snapshot);

        /**
         * @brief Start re-evaluating every @p interval on a background thread.
         *
         * Each tick calls @p evaluate and record()s what it returns; an exception from it is
         * swallowed so the thread survives (the evaluate function is expected to do its own
         * logging). A non-positive @p interval starts no thread: the start-time evaluation stands
         * until the listener restarts. Calling start() while already running is a no-op.
         */
        void start(std::chrono::seconds interval, EvaluateFn evaluate);

        /// Wake and join the thread. Idempotent; safe if never started. Keeps the last snapshot.
        void stop() noexcept;

        /// The latest recorded snapshot (default-constructed before the first record()).
        TlsCertificateSnapshot snapshot() const;

    private:
        mutable std::mutex m_snapshotMutex;
        TlsCertificateSnapshot m_snapshot;

        std::mutex m_waitMutex;
        std::condition_variable m_wakeup;
        std::atomic<bool> m_stopping {false};
        std::thread m_thread;
    };

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_TLS_CERTIFICATE_STATUS_HPP
