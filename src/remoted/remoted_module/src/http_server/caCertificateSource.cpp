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

#include "caCertificateSource.hpp"

#include "ca_bundle/ca_bundle.hpp"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstring>
#include <ctime>
#include <utility>
#include <vector>

namespace remoted::http
{
    namespace
    {
        /// A reference of our own on @p leaf (null stays null). X509_up_ref takes a non-const X509*;
        /// it only bumps the reference count.
        X509Ptr retain(const X509* leaf)
        {
            if (leaf == nullptr || X509_up_ref(const_cast<X509*>(leaf)) != 1)
            {
                return {};
            }
            return X509Ptr {const_cast<X509*>(leaf)};
        }

        /// Whether @p certificate carries a `basicConstraints` extension saying `CA:TRUE` -- the
        /// literal thing `src/init/pkg_installer.sh` greps for on the agent, not OpenSSL's wider
        /// notion of a CA. `ca_bundle::describe()`'s `isCa` comes from X509_check_ca(), which also
        /// answers yes to a certificate with NO basicConstraints at all but `keyCertSign` in its
        /// keyUsage (4), and to a self-signed V1 (3); the installer throws both away, so an export
        /// that trusted it could hand a 4.x agent the one file its own installer discards and
        /// leave it with no anchor. Decoded and freed here on every path; a missing or
        /// undecodable extension is a plain false, which is also what the agent's grep decides.
        bool hasBasicConstraintsCaTrue(const X509* certificate)
        {
            if (certificate == nullptr)
            {
                return false;
            }

            // X509_get_ext_d2i takes a non-const X509* (it caches the extensions it decodes); the
            // decode does not modify the certificate in any observable way.
            auto* constraints = static_cast<BASIC_CONSTRAINTS*>(
                X509_get_ext_d2i(const_cast<X509*>(certificate), NID_basic_constraints, nullptr, nullptr));
            if (constraints == nullptr)
            {
                ERR_clear_error(); // an absent or malformed extension queues nothing worth reporting
                return false;
            }

            const bool isCa = constraints->ca != 0;
            BASIC_CONSTRAINTS_free(constraints);
            return isCa;
        }

        /// Whether two record entries say the same thing. What decides if there is anything left to
        /// write, and whether the entry a write landed is still the one that was pending.
        bool sameEntry(const Entry& left, const Entry& right)
        {
            return left.bundlePath == right.bundlePath && left.fileSha256 == right.fileSha256 &&
                   left.publication == right.publication;
        }
    } // namespace

    CaCertificateSource::CaCertificateSource(std::string path,
                                             const X509* leaf,
                                             FileReader reader,
                                             Clock clock,
                                             LoadOutcome initialRecord,
                                             std::shared_ptr<CaPublicationRecord> record,
                                             std::shared_ptr<CaRecordEventMailbox> mailbox,
                                             VerdictClock verdictClock)
        : m_path {std::move(path)}
        , m_leaf {retain(leaf)}
        , m_reader {reader ? std::move(reader) : FileReader {readFileBounded}}
        , m_clock {clock ? std::move(clock) : Clock {std::chrono::steady_clock::now}}
        , m_verdictClock {std::move(verdictClock)}
        , m_record {std::move(record)}
        , m_mailbox {std::move(mailbox)}
        // Only a record that was READ seeds what this source believes. Everything else starts
        // empty, and the two states that are not answers (unreadable, malformed) also start the
        // source in the mode where its first read stays silent about a history it cannot know.
        , m_recordEffective {initialRecord.status == LoadOutcome::Status::ok ? std::move(initialRecord.entry)
                                                                             : Entry {}}
        , m_recordEverLoaded {initialRecord.status != LoadOutcome::Status::unreadable &&
                              initialRecord.status != LoadOutcome::Status::malformed}
    {
    }

    CaCertificateSnapshot CaCertificateSource::buildLocked(const ca_bundle::ParsedBundle& parsed) const
    {
        CaCertificateSnapshot snapshot;

        if (parsed.certificates.empty())
        {
            // Empty, unparsable or carrying no certificate: all of them mean the same thing to
            // every caller -- there is nothing an agent could bootstrap trust from.
            return snapshot;
        }

        snapshot.pem = serializeCertificates(parsed.certificates);
        snapshot.certificates = parsed.certificates.size();
        snapshot.contentSha256 = ca_bundle::contentSha256(parsed.certificates);

        // Per certificate: the descriptor GET /tls publishes and whether THIS one signs the leaf -- the
        // plain signature fact, deliberately not the chain verdict matchesLeaf carries below.
        snapshot.entries.reserve(parsed.certificates.size());
        for (const auto& certificate : parsed.certificates)
        {
            CaCertificateEntry entry;
            if (auto described = describeCertificate(certificate.get()))
            {
                entry.certificate = std::move(*described);
            }
            entry.signsLeaf = m_leaf && caSignsLeaf(m_leaf.get(), certificate.get());
            snapshot.entries.push_back(std::move(entry));

            if (!snapshot.subjects.empty())
            {
                snapshot.subjects += ", ";
            }
            snapshot.subjects += subjectOfCertificate(certificate.get());
        }

        snapshot.block = parsed.block;
        snapshot.serializedBytes = snapshot.pem.size();

        // No verdict is decided here: matchesLeaf, the vouch and the chain verdict all have a date
        // term, so judgeLocked() decides them on every call, cache hit or not.

        // A serialisation failure leaves nothing to publish: refuse rather than fall back to the
        // bytes we read, which is the whole point of this class.
        if (snapshot.pem.empty())
        {
            return CaCertificateSnapshot {};
        }

        return snapshot;
    }

    CaCertificateSnapshot CaCertificateSource::snapshotLocked()
    {
        std::string contents;
        const ReadResult read = m_reader(m_path, kMaxBytes, contents);

        if (read.status != ReadStatus::Ok)
        {
            // A failed read is a window, not a decision: whatever was being served keeps being
            // served (nothing, if nothing ever was), and the failure travels with the snapshot for
            // the callers that own a logger. m_hash stays as it is, so the same bytes read again
            // once the file is back are still a cache hit.
            ++m_consecutiveFailures;
            m_snapshot.lastReadFailure = ReadFailure {read.status, read.error, m_consecutiveFailures};
            judgeLocked();
            return m_snapshot;
        }

        m_consecutiveFailures = 0;

        auto hash = sha256Hex(contents);
        if (hash == m_hash)
        {
            m_snapshot.lastReadFailure.reset();
            judgeLocked();
            return m_snapshot;
        }

        // Rebuilt from these bytes, whatever they hold: a readable file with no certificate in it is
        // the operator's way of saying "stop serving", and it clears the snapshot at once. The parsed
        // bundle stays behind the snapshot so the verdicts can be re-judged from it on every call
        // without touching the PEM again.
        auto parsed = ca_bundle::parseBundle(contents);
        m_snapshot = buildLocked(parsed);
        m_parsed = m_snapshot.pem.empty() ? ca_bundle::ParsedBundle {} : std::move(parsed);
        // Set after the rebuild and from the same hash the cache is keyed on, so the file's identity
        // travels with the snapshot even when buildLocked() refused everything else in it.
        m_snapshot.fileSha256 = hash;
        // Judged before the record looks at it: applyRecord() derives its event from the vouch.
        judgeLocked();
        // Only the reads that CHANGED the file reach the record: a cache hit above returned long
        // ago, which is what keeps an event from being re-derived (and re-posted) for bytes that
        // were already accounted for. O(1) and I/O-free, so it costs the hot path nothing (C22).
        applyRecord(hash, m_snapshot);
        m_hash = std::move(hash);
        ++m_parses;
        return m_snapshot;
    }

    CaCertificateSnapshot CaCertificateSource::snapshot()
    {
        if (m_path.empty())
        {
            return {};
        }

        // The read runs under the lock too. The file is a few KB and the callers are a rate-limited
        // route, a daily monitor, a metrics scrape and the legacy poller, so serialising them costs
        // nothing measurable -- and it is what makes publication monotonic: with the read outside,
        // the caller that read the OLDER bytes could take the lock last and publish them over the
        // newer ones (issue #39318).
        std::lock_guard<std::mutex> lock {m_mutex};
        return snapshotLocked();
    }

    CaCertificateSource::CaDescriptor CaCertificateSource::descriptor()
    {
        if (m_path.empty())
        {
            // Same guard as snapshot(): nothing configured never has anything to revalidate, so this
            // returns before the reader is touched and before m_lastDescriptorRead/m_hasDescriptor
            // move at all -- a source with no path is not "due for a re-read a second from now", it
            // never becomes due.
            return {};
        }

        // Same mutex as snapshot() (RNF-2): the generation this hands out is one a read produced,
        // never a half-updated one.
        std::lock_guard<std::mutex> lock {m_mutex};

        const auto now = m_clock();
        if (!m_hasDescriptor || now - m_lastDescriptorRead >= kDescriptorRefresh)
        {
            // Inside the window the last verdict stands; past it the file is read again, which is
            // what makes a rotation visible within the second without a notify storm becoming a
            // read storm (CA-15).
            (void)snapshotLocked();
            m_lastDescriptorRead = now;
            m_hasDescriptor = true;
        }

        if (m_snapshot.certificates == 0 || m_snapshot.pem.empty())
        {
            // Nothing servable is not "published as 0": the wire keeps the two apart (`null` vs
            // `0`), so an agent can tell a manager with no bundle from one whose bundle is unstamped.
            return {};
        }

        return CaDescriptor {m_snapshot.publication};
    }

    int CaCertificateSource::leafSignerPem(char* buffer, std::size_t capacity)
    {
        if (buffer == nullptr || capacity == 0)
        {
            // Not "-1, too small": a caller with nowhere to put the answer asked for nothing, and
            // the one caller there is treats <= 0 as "do not deliver" either way.
            return 0;
        }

        // Through snapshot(), not the reader: the same cache, the same read and the same mutex
        // `GET /cacerts` answers from, so the certificate handed to a 4.x agent mid-upgrade comes
        // out of the same bytes the endpoint would serve a 5.x one.
        const auto current = snapshot();
        if (current.pem.empty() || !m_leaf)
        {
            // Nothing servable, or no leaf to build a chain from. Both are "no certificate",
            // not an error: the poller logs the reason and lets the upgrade go ahead.
            return 0;
        }

        // Re-parsed rather than remembered: the snapshot keeps the serialised document, not the
        // individual X509 objects buildLocked() let go of. m_leaf is set in the constructor and has
        // no setter, so reading it outside snapshot()'s lock is safe.
        auto parsed = ca_bundle::parseBundle(current.pem);

        // The moment the delivery is judged against, read once for the whole bundle so two
        // certificates of it can never be measured against two different "now"s. (The chain
        // validation below reads the clock itself, once per candidate; this is the window check
        // that mirrors the agent's installer, and it is the one an operator can reason about.)
        const auto now = std::time(nullptr);

        for (auto& certificate : parsed.certificates)
        {
            // The question is asked of ONE certificate at a time -- a store holding only this
            // candidate -- because what a 4.x agent gets is a single-certificate root-ca.pem: what
            // matters is not that the bundle chains, but WHICH of its certificates the leaf chains
            // to (C33). A signature is not enough and never was: a certificate carrying the CA's
            // key under another subject signs the leaf without being its issuer, and an installer
            // that accepted it would leave the agent trusting an anchor its TLS then rejects --
            // the same defect the publication guard closes, through the back door (objection 8).
            std::vector<X509Ptr> candidateAnchor;
            candidateAnchor.push_back(retain(certificate.get()));
            if (!ca_bundle::leafChainsToAnyCa(m_leaf.get(), candidateAnchor))
            {
                continue;
            }

            // describe() answers what is left about this one certificate: its validity window as
            // this process reads it. Its subject, issuer and CA bit are computed and dropped; no
            // new ca_bundle entry point for a path that runs once per legacy upgrade.
            const auto facts = ca_bundle::describe(certificate.get(), m_leaf.get());

            // Chaining already implies a current CA to OpenSSL, and `src/init/pkg_installer.sh`
            // decides the same thing again on the agent, with `date` and a grep: it refuses a
            // delivered root-ca.pem that is not a CA (no basicConstraints CA:TRUE) or whose
            // validity window does not contain the moment of the upgrade. The checks are kept
            // explicitly so the parity with that script is visible and stays exact -- and the
            // extension is read HERE rather than taken from describe()'s `isCa`, because that one
            // is X509_check_ca() and says yes to more certificates than the installer keeps (no
            // basicConstraints but `keyCertSign`, a self-signed V1): a bundle holding one of those
            // would otherwise be answered with the single file the agent then throws away. Both
            // refusals skip this candidate and keep looking, never end the search: a rotation's
            // overlap is where that earns its keep, with the EXPIRED re-issue of the same key
            // sitting next to the current one and the installer keeping exactly one of them.
            if (!hasBasicConstraintsCaTrue(certificate.get()))
            {
                continue;
            }

            // notBefore/notAfter are 0 only when the ASN.1 time could not be converted at all
            // (ca_bundle::describe()); a date before 1970 is negative and legitimate. An
            // unconvertible window is skipped for the same reason the installer rejects it ("has
            // an unparsable validity period"): nothing here can say whether it is usable. The
            // bounds are inclusive, exactly as pkg_installer.sh compares them.
            if (facts.notBefore == 0 || facts.notAfter == 0 || now < facts.notBefore || now > facts.notAfter)
            {
                continue;
            }

            // Re-serialised from the parsed object, one certificate in the vector: that is what
            // makes the result a single-certificate PEM with no publication block in it, whatever
            // the file around it looks like.
            std::vector<X509Ptr> onlySigner;
            onlySigner.push_back(std::move(certificate));
            const auto pem = serializeCertificates(onlySigner);

            if (pem.empty())
            {
                // A certificate that will not write back out is not one to deliver. Same answer as
                // "nothing chains to it": there is nothing to hand over.
                return 0;
            }

            if (pem.size() > capacity)
            {
                // Told apart from 0 on purpose: the caller's buffer is a compile-time constant, so
                // this is a misconfiguration to look at, not a bundle to fix.
                return -1;
            }

            std::memcpy(buffer, pem.data(), pem.size());
            return static_cast<int>(pem.size());
        }

        // Nothing in this bundle is both an anchor the leaf chains to and one the installer keeps.
        // Better no delivery than one the installer discards: the poller says why and lets the
        // upgrade go ahead without an anchor, which is recoverable, instead of writing one that
        // is not.
        return 0;
    }

    void CaCertificateSource::judgeLocked()
    {
        if (m_parsed.certificates.empty())
        {
            // Nothing servable: nothing to judge, and nothing is vouched for.
            m_snapshot.matchesLeaf.reset();
            m_snapshot.chainValid.reset();
            m_snapshot.chainError.clear();
            m_snapshot.publication = 0;
            m_snapshot.vouchFailure = ca_bundle::GuardFailure::no_certificates;
            return;
        }

        const auto at = m_verdictClock ? std::optional<std::time_t> {m_verdictClock()} : std::nullopt;

        // The one vouch there is (D15): every caller -- the endpoint, the log lines, the notify
        // descriptor -- reads this verdict instead of re-deciding it. What is measured is what would
        // be handed out: the PEM we serialised, not the file.
        const auto vouch = ca_bundle::vouch(m_parsed, m_leaf.get(), m_snapshot.serializedBytes, at);
        m_snapshot.publication = vouch.publication;
        m_snapshot.vouchFailure = vouch.failure;

        if (!m_leaf)
        {
            // With no leaf to check against (a server that has not started) the answer is "unknown",
            // not "mismatch": leafChainsToAnyCa() would say false, and false is what refuses to serve.
            m_snapshot.matchesLeaf.reset();
            m_snapshot.chainValid.reset();
            m_snapshot.chainError.clear();
            return;
        }

        // A real chain validation since C33, with OpenSSL's default flags: a certificate that merely
        // signs the leaf is not one an agent can build a chain to, and this verdict is what the 503
        // and the announced generation are decided from.
        m_snapshot.matchesLeaf = leafChainsToAnyCa(m_leaf.get(), m_parsed.certificates, at);

        // Does the leaf VALIDATE with this bundle as its trust store (chain, dates, CA constraints,
        // server purpose)? Information for the logs and GET /tls, never for the 503 -- see chainValidates().
        const auto chain = chainValidates(m_leaf.get(), m_parsed.certificates, at);
        m_snapshot.chainValid = chain.valid;
        m_snapshot.chainError = chain.error;
    }

    std::uint64_t CaCertificateSource::parses() const
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        return m_parses;
    }

    void CaCertificateSource::applyRecord(const std::string& hash, const CaCertificateSnapshot& built)
    {
        if (!m_record && !m_mailbox)
        {
            // Nothing injected: this source behaves exactly as it did before the record existed.
            return;
        }

        if (built.certificates == 0 || built.pem.empty())
        {
            // Not servable (an emptied file, a PEM we could not parse, a serialisation failure):
            // GET /cacerts already answers 404 and warns about it, and a file nobody can be served
            // from is not evidence that a publication changed. The record keeps what it held and no
            // event is posted (C23, objection 4).
            return;
        }

        // Whether the record's state at construction was an answer. The first read through here is
        // the only one it can affect, so the flag is consumed immediately.
        const bool trusted = m_recordEverLoaded;
        m_recordEverLoaded = true;

        const bool hadAntecedent = !m_recordEffective.fileSha256.empty();

        CaRecordEvent event;
        event.bundlePath = m_path;
        event.recordPath = m_record ? m_record->path() : std::string {};
        event.previousPublication = hadAntecedent ? m_recordEffective.publication : 0;

        std::int64_t publication {0};

        switch (built.vouchFailure)
        {
            case ca_bundle::GuardFailure::none:
                // Vouched: the publication is the block's, whether it is higher or LOWER than the
                // recorded one -- the tool is the only writer and what it last wrote is the truth,
                // so this is never max(record, block) (objection 2).
                publication = built.publication;
                if (!hadAntecedent || m_recordEffective.publication != publication)
                {
                    event.kind = RecordEvent::published_changed;
                }
                break;

            case ca_bundle::GuardFailure::no_block:
                // An ordinary CA file. Which of the two things it is -- never stamped, or stamped
                // and then rewritten -- is exactly what the record is for.
                if (!hadAntecedent)
                {
                    event.kind = trusted ? RecordEvent::first_time_unpublished : RecordEvent::none;
                }
                else if (m_recordEffective.fileSha256 == hash)
                {
                    // These are the bytes the record already describes: a restart, not a change
                    // (CA-14). Nothing to say and nothing to write.
                    return;
                }
                else
                {
                    event.kind = trusted ? RecordEvent::changed_outside_tool : RecordEvent::none;
                }
                break;

            case ca_bundle::GuardFailure::hash_mismatch:
            case ca_bundle::GuardFailure::no_ca_signs_leaf:
            case ca_bundle::GuardFailure::too_many_certificates:
            case ca_bundle::GuardFailure::too_many_bytes:
                // A block is there and a guard refused it: one event carrying WHICH guard and the
                // value it measured (C25), and the bundle counts as unpublished from now on.
                event.kind = RecordEvent::guard_failed;
                event.guard = built.vouchFailure;
                event.observed =
                    built.vouchFailure == ca_bundle::GuardFailure::too_many_certificates
                        ? built.certificates
                        : (built.vouchFailure == ca_bundle::GuardFailure::too_many_bytes ? built.serializedBytes : 0U);
                break;

            case ca_bundle::GuardFailure::no_certificates:
                // Unreachable: a snapshot with nothing servable returned above. Left explicit so a
                // future guard cannot fall through this switch unnoticed.
                return;
        }

        event.publication = publication;

        const Entry updated {m_path, hash, publication};
        if (!hadAntecedent || !sameEntry(updated, m_recordEffective))
        {
            // The effective entry moves whether or not the last write succeeded (objections 5, 7):
            // what this source remembers is the state of the FILE, never the state of the disk it
            // is saved on -- otherwise a failing write would make the same change be announced
            // again at the next read.
            m_recordEffective = updated;
            m_pendingRecord = updated;
        }

        if (m_mailbox && event.kind != RecordEvent::none)
        {
            // O(1), under this source's mutex, into the mailbox's own: the only lock ordering there
            // is (C21b). Nothing here can block on a disk or a logger.
            m_mailbox->post(std::move(event));
        }
    }

    std::vector<CaRecordEvent> CaCertificateSource::drainRecordEvents()
    {
        if (!m_mailbox)
        {
            return {};
        }

        // Deliberately does NOT take m_mutex: the mailbox is independent of the snapshot, so a
        // caller can drain while another is revalidating.
        return m_mailbox->drain();
    }

    void CaCertificateSource::flushPendingRecord()
    {
        if (!m_record)
        {
            return;
        }

        // One writer at a time, and no queue behind it: a second caller (a request while the
        // monitor tick is writing) leaves rather than waits, and its entry is written by whoever
        // comes next -- the pending entry is not consumed until a write succeeds (objection 7).
        std::unique_lock<std::mutex> writer {m_writerMutex, std::try_to_lock};
        if (!writer.owns_lock())
        {
            return;
        }

        std::optional<Entry> pending;
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            pending = m_pendingRecord;
        }

        if (!pending)
        {
            return;
        }

        // The I/O happens here: no m_mutex held, so every reader on the hot path is untouched by
        // however long this takes (RNF-2, C22).
        const bool stored = m_record->store(*pending);
        const int error = m_record->lastError();

        std::lock_guard<std::mutex> lock {m_mutex};

        if (stored)
        {
            if (m_pendingRecord && sameEntry(*m_pendingRecord, *pending))
            {
                // Still the same entry: it is on disk now. A newer one posted while we wrote stays
                // pending for the next call.
                m_pendingRecord.reset();
            }
            m_recordFailurePending = false;

            if (error != 0 && m_mailbox)
            {
                // Written, and renamed into place, but the directory could not be flushed: the
                // record is right, its survival across a power loss is not (objection 15).
                CaRecordEvent event;
                event.kind = RecordEvent::record_unwritable;
                event.bundlePath = m_path;
                event.recordPath = m_record->path();
                event.publication = pending->publication;
                event.error = error;
                event.stored = true;
                m_mailbox->post(std::move(event));
            }
            return;
        }

        if (m_recordFailurePending)
        {
            // Same streak: one line per streak (C19), and the entry stays pending so the next call
            // tries again even if the bundle never changes again (C19b).
            return;
        }

        m_recordFailurePending = true;

        if (m_mailbox)
        {
            CaRecordEvent event;
            event.kind = RecordEvent::record_unwritable;
            event.bundlePath = m_path;
            event.recordPath = m_record->path();
            event.publication = pending->publication;
            event.error = error;
            event.stored = false;
            m_mailbox->post(std::move(event));
        }
    }

    void deliverAndPersistRecordEvents(CaCertificateSource& source,
                                       CaRecordEventMailbox& mailbox,
                                       const CaRecordEventMailbox::Emit& emit)
    {
        // What the read already noticed, in order and exactly once.
        mailbox.deliver(emit);

        // Outside the delivery mutex on purpose (see this function's declaration): the only step
        // here that can touch a disk, and no other consumer of the mailbox may be made to wait for
        // it.
        source.flushPendingRecord();

        // Again, because the write itself posts: a record_unwritable produced right now comes out
        // in THIS call instead of waiting for the next drain (objection 3).
        mailbox.deliver(emit);
    }

    TlsCertificateSnapshot statusFrom(const X509* leaf, const CaCertificateSnapshot& ca)
    {
        TlsCertificateSnapshot status;
        status.expiryDays = daysUntilExpiry(leaf);
        status.leafSubject = subjectOfCertificate(leaf);
        status.caMatchesLeaf = ca.matchesLeaf;
        status.chainValid = ca.chainValid;
        status.chainError = ca.chainError;
        status.caSubjects = ca.subjects;
        status.caReadFailure = ca.lastReadFailure;
        return status;
    }
} // namespace remoted::http
