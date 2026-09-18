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
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <array>
#include <utility>

namespace remoted::http
{
    namespace
    {
        /// Hex SHA-256 of the bytes. Only ever compared against another of these, never published.
        std::string digestOf(std::string_view bytes)
        {
            std::array<unsigned char, SHA256_DIGEST_LENGTH> digest {};
            SHA256(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size(), digest.data());

            static constexpr char kHex[] = "0123456789abcdef";
            std::string hex;
            hex.reserve(digest.size() * 2);
            for (const auto byte : digest)
            {
                hex.push_back(kHex[byte >> 4]);
                hex.push_back(kHex[byte & 0x0F]);
            }
            return hex;
        }

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
    } // namespace

    CaCertificateSource::CaCertificateSource(std::string path, const X509* leaf, FileReader reader, Clock clock)
        : m_path {std::move(path)}
        , m_leaf {retain(leaf)}
        , m_reader {reader ? std::move(reader) : FileReader {readFileBounded}}
        , m_clock {clock ? std::move(clock) : Clock {std::chrono::steady_clock::now}}
    {
    }

    CaCertificateSnapshot CaCertificateSource::buildLocked(std::string_view pem) const
    {
        CaCertificateSnapshot snapshot;

        auto parsed = ca_bundle::parseBundle(pem);
        if (parsed.certificates.empty())
        {
            // Empty, unparsable or carrying no certificate: all of them mean the same thing to
            // every caller -- there is nothing an agent could bootstrap trust from.
            return snapshot;
        }

        snapshot.pem = serializeCertificates(parsed.certificates);
        snapshot.certificates = parsed.certificates.size();

        // The one vouch there is (D15): every caller -- the endpoint, the log lines, the notify
        // descriptor -- reads this verdict instead of re-deciding it, so they cannot disagree about
        // what generation this file is, and the guards run once per read that changed the bytes.
        // What is measured is what would be handed out: the PEM we serialised, not the file.
        const auto vouch = ca_bundle::vouch(parsed, m_leaf.get(), snapshot.pem.size());
        snapshot.publication = vouch.publication;
        snapshot.vouchFailure = vouch.failure;
        snapshot.block = parsed.block;
        snapshot.serializedBytes = snapshot.pem.size();

        // With no leaf to check against (a server that has not started) the answer is "unknown",
        // not "mismatch": anyCaSignsLeaf() would say false, and false is what refuses to serve.
        if (m_leaf)
        {
            snapshot.matchesLeaf = anyCaSignsLeaf(m_leaf.get(), parsed.certificates);

            // Separately from the signature: does the leaf VALIDATE with this bundle as its trust
            // store (chain, dates, CA constraints, server purpose)? Information for the logs, never
            // for the 503 -- see chainValidates().
            const auto chain = chainValidates(m_leaf.get(), parsed.certificates);
            snapshot.chainValid = chain.valid;
            snapshot.chainError = chain.error;
        }

        for (const auto& certificate : parsed.certificates)
        {
            if (!snapshot.subjects.empty())
            {
                snapshot.subjects += ", ";
            }
            snapshot.subjects += subjectOfCertificate(certificate.get());
        }

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
            return m_snapshot;
        }

        m_consecutiveFailures = 0;

        auto hash = digestOf(contents);
        if (hash == m_hash)
        {
            m_snapshot.lastReadFailure.reset();
            return m_snapshot;
        }

        // Rebuilt from these bytes, whatever they hold: a readable file with no certificate in it is
        // the operator's way of saying "stop serving", and it clears the snapshot at once.
        m_snapshot = buildLocked(contents);
        // Set after the rebuild and from the same hash the cache is keyed on, so the file's identity
        // travels with the snapshot even when buildLocked() refused everything else in it.
        m_snapshot.fileSha256 = hash;
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

    std::uint64_t CaCertificateSource::parses() const
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        return m_parses;
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
        status.caPublication = ca.publication;
        status.caVouchFailure = ca.vouchFailure;
        status.caCertificates = ca.certificates;
        status.caSerializedBytes = ca.serializedBytes;
        return status;
    }
} // namespace remoted::http
