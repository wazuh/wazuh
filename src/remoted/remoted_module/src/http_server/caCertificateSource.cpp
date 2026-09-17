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
        , m_clock {std::move(clock)}
    {
    }

    CaCertificateSnapshot CaCertificateSource::buildLocked(const std::vector<X509Ptr>& certificates) const
    {
        CaCertificateSnapshot snapshot;

        if (certificates.empty())
        {
            // Empty, unparsable or carrying no certificate: all of them mean the same thing to
            // every caller -- there is nothing an agent could bootstrap trust from.
            return snapshot;
        }

        snapshot.pem = serializeCertificates(certificates);
        snapshot.serializedBytes = snapshot.pem.size();
        snapshot.certificates = certificates.size();
        snapshot.contentSha256 = contentSha256(certificates);

        // Per certificate: the descriptor GET /tls publishes and whether THIS one signs the leaf.
        // With no leaf to check against (a server that has not started) the bundle-level answer is
        // "unknown", not "mismatch": false is what refuses to serve.
        bool anySigns = false;
        snapshot.entries.reserve(certificates.size());
        for (const auto& certificate : certificates)
        {
            CaCertificateEntry entry;
            if (auto described = describeCertificate(certificate.get()))
            {
                entry.certificate = std::move(*described);
            }
            entry.signsLeaf = m_leaf && caSignsLeaf(m_leaf.get(), certificate.get());
            anySigns = anySigns || entry.signsLeaf;
            snapshot.entries.push_back(std::move(entry));

            if (!snapshot.subjects.empty())
            {
                snapshot.subjects += ", ";
            }
            snapshot.subjects += subjectOfCertificate(certificate.get());
        }

        if (m_leaf)
        {
            // The same value anyCaSignsLeaf() gives: the OR of the per-certificate checks above. The
            // chain verdict is deliberately NOT computed here: it has a date term, so snapshot() asks
            // validateChainLocked() for it on every call, cache hit or not.
            snapshot.matchesLeaf = anySigns;
        }

        // A serialisation failure leaves nothing to publish: refuse rather than fall back to the
        // bytes we read, which is the whole point of this class.
        if (snapshot.pem.empty())
        {
            return CaCertificateSnapshot {};
        }

        return snapshot;
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
        }
        else
        {
            m_consecutiveFailures = 0;

            auto hash = digestOf(contents);
            if (hash != m_hash)
            {
                // Rebuilt from these bytes, whatever they hold: a readable file with no certificate in it
                // is the operator's way of saying "stop serving", and it clears the snapshot at once.
                auto parsed = parseCertificates(contents);
                m_snapshot = buildLocked(parsed.certificates);
                m_certificates = m_snapshot.pem.empty() ? std::vector<X509Ptr> {} : std::move(parsed.certificates);
                m_hash = std::move(hash);
                ++m_parses;
            }
            m_snapshot.lastReadFailure.reset();
        }

        // The one date-dependent verdict, judged now for whatever is being returned: the bundle just
        // parsed, the cached one, or the last good one behind a failed read.
        validateChainLocked();
        return m_snapshot;
    }

    void CaCertificateSource::validateChainLocked()
    {
        if (!m_leaf || m_certificates.empty())
        {
            // Nothing to validate against (no leaf yet, or no bundle): unknown, never "invalid".
            m_snapshot.chainValid.reset();
            m_snapshot.chainError.clear();
            return;
        }

        // Does the leaf VALIDATE with this bundle as its trust store (chain, dates, CA constraints,
        // server purpose)? Information for the logs and GET /tls, never for the 503 -- see chainValidates().
        const auto chain = chainValidates(
            m_leaf.get(), m_certificates, m_clock ? std::optional<std::time_t> {m_clock()} : std::nullopt);
        m_snapshot.chainValid = chain.valid;
        m_snapshot.chainError = chain.error;
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
        return status;
    }
} // namespace remoted::http
