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
 * can carry TlsCertificateSnapshot without leaking the OpenSSL API into every endpoint -- a
 * property ca_bundle/ca_bundle.hpp keeps as well.
 *
 * Reading, hashing and vouching for the CA bundle itself is shared_modules/ca_bundle's (issue
 * #39319): X509Ptr, serializeCertificates() and anyCaSignsLeaf() live there now and are re-exported
 * below, so every user of this header keeps its spelling.
 */

#include "fileRead.hpp"

#include "ca_bundle/ca_bundle.hpp"

#include <openssl/types.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace remoted::http
{
    // Owned by shared_modules/ca_bundle now, re-exported (using-declarations, not new types) so the
    // ~40 places that spell them `remoted::http::X509Ptr` / serializeCertificates() /
    // anyCaSignsLeaf() -- RestinioHttpServer.cpp, caCertificateSource.{hpp,cpp}, the tests' PKI --
    // did not have to change when the parsing moved out. The bundle READER is ca_bundle's
    // parseBundle(), which returns the publication block too, so it is called by its own name.
    using ca_bundle::anyCaSignsLeaf;
    using ca_bundle::serializeCertificates;
    using ca_bundle::X509Ptr;

    /// Subject line of a certificate, for logs and snapshots. Empty for a null certificate.
    std::string subjectOfCertificate(const X509* certificate);

    /**
     * @brief Whole days until @p certificate's notAfter, negative once expired.
     *
     * Truncated toward zero, except that an already-expired certificate never reads 0: the first
     * 24 h past notAfter read -1, so "negative" is a strict synonym of "expired". nullopt for a
     * null certificate or one whose notAfter cannot be compared.
     */
    std::optional<int> daysUntilExpiry(const X509* certificate);

    /// What chainValidates() found: nullopt when there was nothing to validate against.
    struct ChainVerdict
    {
        std::optional<bool> valid;
        std::string error; ///< OpenSSL's reason (X509_verify_cert_error_string) when valid is false; empty otherwise.
    };

    /**
     * @brief Whether @p leaf VALIDATES with @p cas as its trust store: chain building, validity
     *        dates, basicConstraints/keyUsage of every CA on the path, and server purpose.
     *
     * The store holds the bundle and nothing else -- no intermediates borrowed from the listener's
     * own certificate file -- because the bundle is all an agent bootstrapping from `GET /cacerts`
     * will ever hold. `X509_V_FLAG_PARTIAL_CHAIN` makes any certificate of the bundle a trust anchor
     * even when it is not self-signed, so `root-ca.pem` may carry a purchased intermediate that
     * signed the leaf as well as a private self-signed CA. Evaluated against the current time.
     *
     * Not what decides the 503: anyCaSignsLeaf() is. This is information for the operator -- a CA
     * that signs the leaf but has expired, or lacks `CA:TRUE`, still "matches" and yet no verifying
     * agent could use it -- surfaced through the snapshots and the certificate log lines.
     */
    ChainVerdict chainValidates(const X509* leaf, const std::vector<X509Ptr>& cas);

    /**
     * @brief The names that describe this host to itself, and to nobody else.
     *
     * `localhost`, `localhost.localdomain`, whatever `gethostname()` returns, and -- when that is
     * fully qualified -- its short form as well. Used by leafHasUsableSan() as the set to subtract.
     *
     * Split out from leafHasUsableSan() so the filter table can be unit-tested against a fixed list
     * instead of against whatever the build machine happens to be called.
     */
    std::vector<std::string> localHostNames();

    /**
     * @brief Whether @p leaf carries a subjectAltName entry some remote agent could plausibly dial.
     *
     * Answers the one certificate question this module can settle on its own. The one it CANNOT is
     * "does the leaf cover the address this agent will dial": behind NAT, a load balancer, or when
     * an agent is pinned to a worker, the manager does not know that address, and the agent checks
     * it for real at upgrade time (pkg_installer.sh probes its own configured server with
     * verification on). So this is deliberately the weaker, decidable question.
     *
     * A SAN entry counts as usable unless it is one of:
     *   - an iPAddress in 127.0.0.0/8 or ::1;
     *   - a dNSName in @p localNames (case-insensitive).
     * Entries of any other type (URI, email, ...) are ignored: none of them is something a TLS
     * client matches a server against.
     *
     * False for a certificate with no SAN extension at all, and false for one whose only entries are
     * loopback and the local hostname -- the shape a self-signed quickstart certificate has. Both
     * mean no agent can ever verify this manager at verification_mode `full`, whatever it dials.
     *
     * Never a reason to refuse anything: an operator whose agents reach the manager by a name that
     * is genuinely absent from the certificate is already broken in a way this cannot see, and one
     * whose SANs merely look unusual here must not have upgrades blocked over a heuristic.
     */
    bool leafHasUsableSan(const X509* leaf, const std::vector<std::string>& localNames);

    /// @copydoc leafHasUsableSan(const X509*, const std::vector<std::string>&)
    /// Uses localHostNames() as the subtracted set.
    bool leafHasUsableSan(const X509* leaf);

    /**
     * @brief Point-in-time result of one certificate evaluation.
     *
     * Published two ways: by the facade as the `remoted.server.tls.*` pull metrics, and to
     * `GET /cacerts`, which refuses (503) to hand out a CA that does not sign the served leaf.
     * The default-constructed value is what a server that never started reports.
     */
    struct TlsCertificateSnapshot
    {
        std::optional<int> expiryDays;            ///< Days until the served leaf expires; see daysUntilExpiry().
        std::optional<bool> caMatchesLeaf;        ///< true/false when the CA file was readable and carried at
                                                  ///< least one certificate; nullopt when it was not (a
                                                  ///< missing CA is "unknown", never "mismatch").
        std::uint64_t evaluations {0};            ///< How many evaluations produced snapshots so far (1 after
                                                  ///< the start-time one; +1 per monitor tick).
        std::string leafSubject;                  ///< Subject of the served leaf, for the log lines.
        std::string caSubjects;                   ///< Subjects of the certificates read from the CA file,
                                                  ///< comma-separated; empty when none was readable.
        std::optional<bool> chainValid;           ///< Whether the served leaf validates with the CA file as its trust
                                                  ///< store (chain, dates, constraints); nullopt when there was nothing
                                                  ///< to evaluate against.
        std::string chainError;                   ///< OpenSSL's reason when chainValid is false; empty otherwise.
        std::optional<ReadFailure> caReadFailure; ///< Present while the CA file cannot be read: the CA fields
                                                  ///< above then describe the last GOOD read of it (or are empty
                                                  ///< when there never was one), not the file as it is now.

        /// Generation the CA bundle is published under (RF-2), 0 when no guard vouched for it --
        /// what the logs announce and what the notify path tells agents.
        std::int64_t caPublication {0};
        /// Which guard refused to vouch for the bundle, or `none`; `no_certificates` for a status
        /// that never had a bundle to vouch for. What names the cause in the log line.
        ca_bundle::GuardFailure caVouchFailure {ca_bundle::GuardFailure::no_certificates};
        /// How many certificates the CA bundle carried at the last good read; 0 when there was none.
        /// What the `too_many_certificates` log line names alongside ca_bundle::kMaxCertificates.
        std::size_t caCertificates {0};
        /// Size of the PEM this process would serve for the bundle; 0 when there was none. What the
        /// `too_many_bytes` log line names alongside ca_bundle::kMaxSerializedBytes.
        std::size_t caSerializedBytes {0};
    };

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
