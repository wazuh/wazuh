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

#include <array>
#include <fstream>
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

        /**
         * @brief Read at most @p maxBytes of @p path.
         *
         * false when the file cannot be opened or is larger than the cap; the caller treats both as
         * "nothing to serve". The cap is the difference from the old per-request read, which pulled
         * in whatever size the file happened to be.
         */
        bool readBounded(const std::string& path, std::size_t maxBytes, std::string& contents)
        {
            std::ifstream file {path, std::ios::binary};
            if (!file.is_open())
            {
                return false;
            }

            contents.assign(std::istreambuf_iterator<char> {file}, std::istreambuf_iterator<char> {});
            if (contents.size() > maxBytes)
            {
                contents.clear();
                return false;
            }

            return true;
        }
    } // namespace

    CaCertificateSource::CaCertificateSource(std::string path, const X509* leaf)
        : m_path {std::move(path)}
        , m_leaf {leaf}
    {
    }

    CaCertificateSnapshot CaCertificateSource::buildLocked(std::string_view pem) const
    {
        CaCertificateSnapshot snapshot;

        auto parsed = parseCertificates(pem);
        if (parsed.certificates.empty())
        {
            // Missing, empty, unparsable or carrying no certificate: all of them mean the same
            // thing to every caller -- there is nothing an agent could bootstrap trust from.
            return snapshot;
        }

        snapshot.pem = serializeCertificates(parsed.certificates);
        snapshot.certificates = parsed.certificates.size();

        // With no leaf to check against (a server that has not started) the answer is "unknown",
        // not "mismatch": anyCaSignsLeaf() would say false, and false is what refuses to serve.
        if (m_leaf != nullptr)
        {
            snapshot.matchesLeaf = anyCaSignsLeaf(m_leaf, parsed.certificates);
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

    CaCertificateSnapshot CaCertificateSource::snapshot()
    {
        if (m_path.empty())
        {
            return {};
        }

        std::string contents;
        const bool read = readBounded(m_path, kMaxBytes, contents);

        std::lock_guard<std::mutex> lock {m_mutex};

        if (!read)
        {
            m_hash.clear();
            m_snapshot = CaCertificateSnapshot {};
            return m_snapshot;
        }

        auto hash = digestOf(contents);
        if (hash == m_hash)
        {
            return m_snapshot;
        }

        m_snapshot = buildLocked(contents);
        m_hash = std::move(hash);
        ++m_parses;

        return m_snapshot;
    }

    std::uint64_t CaCertificateSource::parses() const
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        return m_parses;
    }
} // namespace remoted::http
