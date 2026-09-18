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
 *
 * That same read also decides whether the bundle is PUBLISHED (issue #39319): ca_bundle::vouch()
 * runs on it once, and its verdict -- the generation, or 0 and the guard that refused -- travels in
 * the snapshot, so the endpoint, the certificate log lines and the notify path cannot disagree about
 * what generation this file is. Publishing is a separate question from serving: an unvouched bundle
 * is handed out exactly as a vouched one. descriptor() is the view for the callers on the hot path,
 * one per control notify: it revalidates under the same mutex at most once every kDescriptorRefresh,
 * so a notify storm costs one read per second while a rotation is still seen within the second.
 *
 * What the file cannot say about itself is whether it was EVER published: an ordinary CA file and a
 * published bundle somebody rewrote by hand look identical. That is what the optional publication
 * record adds (CaPublicationRecord), and the division of labour is deliberate (C22): the record is
 * READ once, before this source is handed to anyone, and arrives through the constructor; the
 * comparison that turns a changed file into an event is O(1) and runs under the mutex with no I/O
 * at all; the event goes to a mailbox the source only fills; and the WRITE happens in
 * flushPendingRecord(), outside the mutex, called by whoever drained the mailbox. So no caller on
 * the hot path ever waits for a disk, an event is logged exactly once by exactly one of the three
 * callers that own a logger, and a record that cannot be written costs one warning and a retry --
 * never a publication (C19, C19b).
 */

#include "caPublicationRecord.hpp"
#include "caRecordEvents.hpp"
#include "fileRead.hpp"
#include "tlsCertificateStatus.hpp"

#include "ca_bundle/ca_bundle.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace remoted::http
{
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

        /// The generation this bundle may be announced under (RF-2): the publication its block
        /// carries once every guard passed, 0 when any of them refused -- and 0 is what an agent
        /// reads as "this manager has no published bundle".
        std::int64_t publication {0};
        /// Which guard refused to vouch for the bundle, or `none`. Defaults to `no_certificates`
        /// rather than `none`: a snapshot buildLocked() never got to vouch for (nothing to serve,
        /// a serialisation failure) must not read as "vouched for" because the field was untouched.
        ca_bundle::GuardFailure vouchFailure {ca_bundle::GuardFailure::no_certificates};
        /// The publication block the file carries, if any. Absent means the bundle was never
        /// stamped -- an ordinary CA file -- which is a different state from a block that does not
        /// describe the certificates next to it.
        std::optional<ca_bundle::PublicationBlock> block;
        /// Size of `pem`: what the byte guard measured, and what `GET /cacerts` would hand out.
        std::size_t serializedBytes {0};
        /// SHA-256 of the FILE's bytes -- the cache key, and what tells a bundle rewritten outside
        /// the tool from one that never changed. Not the block's Content-SHA256, which hashes what
        /// the certificates ARE (ca_bundle::contentSha256()).
        std::string fileSha256;
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
        /// How descriptor() reads the clock. A test hands it a time it moves by hand.
        using Clock = std::function<std::chrono::steady_clock::time_point()>;

        /// How long descriptor() may answer without reading the file again: one read per second per
        /// node is the whole cost the notify path is allowed to add, however many agents ask (C18).
        static constexpr std::chrono::seconds kDescriptorRefresh {1};

        /// What the notify path needs from the bundle, and nothing else: the generation to tell an
        /// agent about. `nullopt` means there is no servable bundle at all (`null` on the wire); 0
        /// means there is one and it is not published. No hash of anything ever leaves here.
        struct CaDescriptor
        {
            std::optional<std::int64_t> generation;
        };

        /// Largest CA file served. A bundle is a few KB; past this the file is refused as TooLarge,
        /// and never more than kMaxBytes + 1 bytes of it are requested from the reader.
        static constexpr std::size_t kMaxBytes {1024U * 1024U};

        /**
         * @param path Configured CA path; an empty one yields an empty snapshot forever.
         * @param leaf Certificate the listener serves. The source takes its own reference (X509_up_ref),
         *             so a later start() replacing the listener's leaf cannot free it under a caller
         *             that still holds this source (the metrics scrape, the legacy poller).
         * @param reader How the bytes are read: readFileBounded() unless a test says otherwise. An
         *               empty function falls back to the default rather than being called.
         * @param clock How descriptor() tells the time when it decides whether its answer is still
         *              fresh. Injectable so the refresh window is testable without sleeping; an
         *              empty function falls back to the default rather than being called.
         * @param initialRecord What the publication record said when it was read, ONCE, before this
         *              source existed (C22): reading it here would put file I/O under the hot-path
         *              mutex. Only `ok` seeds the effective entry; `unreadable`/`malformed` make the
         *              first read of the bundle stay silent about "never published" and "changed
         *              outside the tool", because a record we could not read is not evidence of
         *              either (C23).
         * @param record Where the effective entry is persisted, outside the mutex, by
         *              flushPendingRecord(). Null keeps this source exactly as it was before the
         *              record existed: it remembers nothing and emits nothing.
         * @param mailbox Where the events go until a caller with a logger drains them. Null also
         *              means no events (the two are injected together in production).
         */
        CaCertificateSource(std::string path,
                            const X509* leaf,
                            FileReader reader = readFileBounded,
                            Clock clock = std::chrono::steady_clock::now,
                            LoadOutcome initialRecord = {},
                            std::shared_ptr<CaPublicationRecord> record = nullptr,
                            std::shared_ptr<CaRecordEventMailbox> mailbox = nullptr);

        /**
         * @brief Current state of the file: cached while its content hash is unchanged.
         *
         * When the read fails, the last good snapshot comes back unchanged with `lastReadFailure`
         * set; when it succeeds, `lastReadFailure` is cleared, and identical bytes are still a cache
         * hit even across a failure in between.
         */
        CaCertificateSnapshot snapshot();

        /**
         * @brief The vouched-for generation, revalidated at most once every kDescriptorRefresh.
         *
         * One call per control notify, and a notify storm is exactly what this must not turn into a
         * read storm -- while a rotation still has to be seen within the second (CA-15). Runs under
         * the same mutex as snapshot(), so the generation it publishes is never older than what the
         * last read saw, and the first call always reads.
         */
        CaDescriptor descriptor();

        /**
         * @brief The ONE certificate of this bundle that signs the served leaf, re-serialised into
         *        @p buffer -- a single certificate, never the bundle and never the `##` block (RF-7).
         *
         * For the legacy WPK delivery, and for nothing else. `src/init/pkg_installer.sh` refuses a
         * `root-ca.pem` drop-in carrying more than one `-----BEGIN CERTIFICATE-----`, so handing a
         * 4.x agent mid-upgrade the bundle a rotation's overlap makes of this file would leave it
         * with no anchor at all (C7). What the agent needs is the one CA that verifies this
         * listener, and that is what comes out of here: the FIRST certificate of the snapshot whose
         * signature is on the served leaf, written back out by this process from the parsed X.509
         * object rather than copied out of the file.
         *
         * Reads through snapshot(), so these bytes come from the same cache, the same read and the
         * same mutex `GET /cacerts` answers from -- the two paths can never disagree about which
         * file they are talking about. The re-parse it costs is deliberate: this runs once per
         * upgrade of one pre-v5.0.0 agent, never on a hot path.
         *
         * @param buffer Where the PEM is written. Not NUL-terminated: the return value is the length.
         * @param capacity Bytes available at @p buffer.
         * @return Bytes written (> 0); 0 when no certificate of the bundle signs the leaf, when
         *         there is no servable bundle or when there is no served leaf to check against;
         *         -1 when @p capacity is too small for the certificate (nothing is written).
         */
        int leafSignerPem(char* buffer, std::size_t capacity);

        /// How many times the bytes were actually parsed. Only the tests care: it is what proves
        /// the cache holds when the file did not change, and gives way when it did.
        std::uint64_t parses() const;

        /**
         * @brief Takes the publication events noticed since the last call, in order.
         *
         * For the three callers that own a logger: the transport at start and on the daily tick,
         * and the `GET /cacerts` handler before it answers. Each event comes out of exactly one of
         * them, because draining REMOVES it (C21b) -- so a guard that starts failing between two
         * ticks is said in the next request instead of a day later, and nothing is said twice.
         * Takes no lock of this source: the mailbox has its own.
         */
        std::vector<CaRecordEvent> drainRecordEvents();

        /**
         * @brief Writes the effective entry to the record, if it is not there yet.
         *
         * Runs OUTSIDE the source's mutex, under a writer mutex of its own taken with try_lock: a
         * second caller arriving while one is writing returns at once rather than queueing, and a
         * reader on the hot path never waits for the disk (RNF-2, C22). Retries as long as
         * something is pending -- whether or not the file changed again -- so a permission repaired
         * hours after the failure is persisted at the next revalidation, not at the next rotation
         * (C19b). A failure is announced once per streak, and never in place of the bundle's own
         * event.
         */
        void flushPendingRecord();

    private:
        CaCertificateSnapshot buildLocked(std::string_view pem) const;

        /**
         * @brief Derives the record event for @p built and updates what this source remembers.
         *
         * Called from snapshotLocked() with m_mutex held, only when the file's hash changed, and it
         * is O(1) on purpose: a comparison, two assignments and a post(). No I/O whatsoever (C22)
         * -- the write it makes necessary is left pending for flushPendingRecord().
         *
         * Follows the table of 02-diseno.md §2.3 row by row, against the EFFECTIVE entry in memory
         * (never against the disk): the effective entry is updated whether or not the previous
         * write succeeded, so a failing disk can never make the same bundle change be announced
         * twice.
         */
        void applyRecord(const std::string& hash, const CaCertificateSnapshot& built);

        /// snapshot()'s whole body with m_mutex already held: the read, the cache check and the
        /// rebuild. descriptor() revalidates through it, so a revalidation takes the lock once.
        CaCertificateSnapshot snapshotLocked();

        const std::string m_path;
        X509Ptr m_leaf; ///< Our own reference to the served leaf; null when the caller passed none.
        const FileReader m_reader;
        const Clock m_clock;

        mutable std::mutex m_mutex;
        std::string m_hash; ///< SHA-256 of the bytes behind m_snapshot; empty before the first good read.
        CaCertificateSnapshot m_snapshot;
        std::uint64_t m_parses {0};
        std::uint64_t m_consecutiveFailures {0};                       ///< Reset by every successful read.
        std::chrono::steady_clock::time_point m_lastDescriptorRead {}; ///< When descriptor() last revalidated.
        /// False until descriptor() has revalidated once, so the first call always reads whatever
        /// time the injected clock starts at -- an epoch-zero start is not "just revalidated".
        bool m_hasDescriptor {false};

        /// Where the effective entry is persisted; null when no record was injected.
        const std::shared_ptr<CaPublicationRecord> m_record;
        /// Where the events wait for a logger; null when none was injected.
        const std::shared_ptr<CaRecordEventMailbox> m_mailbox;
        /// What this source believes the record says, which is the only thing events are derived
        /// from. Guarded by m_mutex. An empty fileSha256 means "no antecedent at all".
        Entry m_recordEffective;
        /// Whether the record's state at construction was an ANSWER (`ok` or `absent`) rather than
        /// a failure to read it. False suppresses exactly two events on the first read --
        /// `first_time_unpublished` and `changed_outside_tool` -- because neither can be concluded
        /// from a record we could not read (C23). Set once the first read has been through here.
        bool m_recordEverLoaded {false};
        /// The entry flushPendingRecord() still has to write, if any. Guarded by m_mutex.
        std::optional<Entry> m_pendingRecord;
        /// True while a streak of failed writes is in progress, so the warning is emitted once per
        /// streak and the retry keeps happening. Guarded by m_mutex.
        bool m_recordFailurePending {false};
        /// One writer at a time, and never a queue: flushPendingRecord() takes this with try_lock.
        /// Separate from m_mutex on purpose -- holding this one blocks no reader.
        std::mutex m_writerMutex;
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
