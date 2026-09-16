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

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
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

        /// Owns the descriptor for the duration of one read.
        class FileDescriptor final
        {
        public:
            explicit FileDescriptor(int fd) noexcept
                : m_fd {fd}
            {
            }
            ~FileDescriptor()
            {
                if (m_fd >= 0)
                {
                    ::close(m_fd);
                }
            }
            FileDescriptor(const FileDescriptor&) = delete;
            FileDescriptor& operator=(const FileDescriptor&) = delete;

            int get() const noexcept
            {
                return m_fd;
            }

        private:
            int m_fd;
        };
    } // namespace

    ReadResult readFileBounded(const std::string& path, std::size_t maxBytes, std::string& contents)
    {
        contents.clear();

        // O_CLOEXEC: remoted forks helpers, and a descriptor on the CA file has no business in them.
        const FileDescriptor file {::open(path.c_str(), O_RDONLY | O_CLOEXEC)};
        if (file.get() < 0)
        {
            return {ReadStatus::CannotOpen, errno};
        }

        // One byte past the cap is the whole trick: if it ever arrives the file is too large, and
        // nothing beyond it is ever requested -- so the memory this costs is the file's real size
        // up to the cap, never whatever size the file happens to be. Small chunks, because the
        // common case is a few KB and a per-request megabyte buffer would be its own regression.
        static constexpr std::size_t kChunk {16U * 1024U};
        const std::size_t limit = maxBytes + 1;
        std::array<char, kChunk> chunk {};
        std::size_t total = 0;

        while (total < limit)
        {
            const std::size_t wanted = std::min(kChunk, limit - total);
            const ssize_t got = ::read(file.get(), chunk.data(), wanted);
            if (got < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                contents.clear();
                return {ReadStatus::ReadError, errno};
            }
            if (got == 0)
            {
                break; // EOF: the whole file fit under the cap.
            }
            contents.append(chunk.data(), static_cast<std::size_t>(got));
            total += static_cast<std::size_t>(got);
        }

        if (total > maxBytes)
        {
            contents.clear();
            return {ReadStatus::TooLarge, 0};
        }

        return {};
    }

    CaCertificateSource::CaCertificateSource(std::string path, const X509* leaf, FileReader reader)
        : m_path {std::move(path)}
        , m_leaf {leaf}
        , m_reader {reader ? std::move(reader) : FileReader {readFileBounded}}
    {
    }

    CaCertificateSnapshot CaCertificateSource::buildLocked(std::string_view pem) const
    {
        CaCertificateSnapshot snapshot;

        auto parsed = parseCertificates(pem);
        if (parsed.certificates.empty())
        {
            // Empty, unparsable or carrying no certificate: all of them mean the same thing to
            // every caller -- there is nothing an agent could bootstrap trust from.
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
