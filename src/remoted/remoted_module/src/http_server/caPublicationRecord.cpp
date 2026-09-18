/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * September 18, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "caPublicationRecord.hpp"

#include "json.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <utility>

namespace remoted::http
{
    namespace
    {
        /// Everything before the last '/', or "." when the path carries no directory at all.
        std::string directoryOf(const std::string& path)
        {
            const auto slash = path.find_last_of('/');
            if (slash == std::string::npos)
            {
                return ".";
            }
            return slash == 0 ? "/" : path.substr(0, slash);
        }

        /**
         * @brief @p path with every symlink and `..` resolved, as far as it can be.
         *
         * realpath(3) needs the whole path to exist, and the record usually does not exist yet, so
         * a path that cannot be resolved falls back to resolving its DIRECTORY and appending the
         * name: enough to catch a record pointed at the bundle through a symlinked directory. When
         * even that fails (the directory is not there either) the path comes back untouched --
         * which still compares equal to itself, so the aliasing check stays meaningful.
         */
        std::string resolved(const std::string& path)
        {
            if (path.empty())
            {
                return path;
            }

            if (char* const exact = ::realpath(path.c_str(), nullptr); exact != nullptr)
            {
                std::string result {exact};
                ::free(exact);
                return result;
            }

            const auto directory = directoryOf(path);
            if (char* const parent = ::realpath(directory.c_str(), nullptr); parent != nullptr)
            {
                std::string result {parent};
                ::free(parent);
                const auto slash = path.find_last_of('/');
                const auto name = slash == std::string::npos ? path : path.substr(slash + 1);
                if (result.empty() || result.back() != '/')
                {
                    result.push_back('/');
                }
                result += name;
                return result;
            }

            return path;
        }
    } // namespace

    CaPublicationRecord::CaPublicationRecord(std::string path, RecordIo io)
        : m_path {std::move(path)}
        , m_io {std::move(io)}
    {
    }

    bool CaPublicationRecord::aliases(const std::string& bundlePath) const
    {
        if (m_path.empty() || bundlePath.empty())
        {
            return false;
        }

        // Fail-closed (C23): if these two resolve to one file, the record would be written OVER the
        // bundle. Nothing this feature does may modify that file (RF-8, CA-19), so neither call
        // proceeds -- and a configuration that makes this true is refused on every attempt, not
        // fixed up silently.
        return resolved(m_path) == resolved(bundlePath);
    }

    LoadOutcome CaPublicationRecord::load(const std::string& bundlePath) const
    {
        LoadOutcome outcome;

        if (m_path.empty())
        {
            return outcome; // No record configured: an absence, and a permanent one.
        }

        if (aliases(bundlePath))
        {
            outcome.status = LoadOutcome::Status::foreign_path;
            outcome.error = EINVAL;
            return outcome;
        }

        std::string contents;
        const auto read =
            m_io.read ? m_io.read(m_path, kMaxBytes, contents) : readFileBounded(m_path, kMaxBytes, contents);

        switch (read.status)
        {
            case ReadStatus::Ok: break;

            case ReadStatus::CannotOpen:
                // A missing record is the ordinary state of a fresh node; anything else (a
                // permission change, a path whose parent is not a directory) is a record we may
                // have and cannot read, which must never be reported as "never published".
                if (read.error == ENOENT || read.error == ENOTDIR)
                {
                    outcome.status = LoadOutcome::Status::absent;
                    return outcome;
                }
                outcome.status = LoadOutcome::Status::unreadable;
                outcome.error = read.error;
                return outcome;

            case ReadStatus::ReadError:
                outcome.status = LoadOutcome::Status::unreadable;
                outcome.error = read.error;
                return outcome;

            case ReadStatus::TooLarge:
                // Over kMaxBytes it is not something we wrote, so it is not parsed at all.
                outcome.status = LoadOutcome::Status::malformed;
                return outcome;
        }

        const auto document = nlohmann::json::parse(contents, nullptr, false);
        if (document.is_discarded() || !document.is_object())
        {
            outcome.status = LoadOutcome::Status::malformed;
            return outcome;
        }

        const auto version = document.find("version");
        const auto bundle = document.find("bundle_path");
        const auto digest = document.find("file_sha256");
        const auto publication = document.find("publication");

        // Every field's TYPE is checked, not just its presence: a hand-edited record with a string
        // where a number belongs is malformed, never a publication of 0 attributed to this bundle
        // (objection 3).
        if (version == document.end() || !version->is_number_integer() || version->get<int>() != kVersion ||
            bundle == document.end() || !bundle->is_string() || digest == document.end() || !digest->is_string() ||
            publication == document.end() || !publication->is_number_integer())
        {
            outcome.status = LoadOutcome::Status::malformed;
            return outcome;
        }

        Entry entry;
        entry.bundlePath = bundle->get<std::string>();
        entry.fileSha256 = digest->get<std::string>();
        entry.publication = publication->get<std::int64_t>();

        if (entry.bundlePath.empty() || entry.fileSha256.empty() || entry.publication < 0)
        {
            outcome.status = LoadOutcome::Status::malformed;
            return outcome;
        }

        if (resolved(entry.bundlePath) != resolved(bundlePath))
        {
            // A record about another file lends nothing to this one: treated as an absence by the
            // caller, so a publication is never attributed to a bundle it does not describe
            // (objection 1).
            outcome.status = LoadOutcome::Status::foreign_path;
            return outcome;
        }

        outcome.entry = std::move(entry);
        outcome.status = LoadOutcome::Status::ok;
        return outcome;
    }

    bool CaPublicationRecord::store(const Entry& entry)
    {
        if (m_path.empty())
        {
            m_lastError = EINVAL;
            return false;
        }

        if (aliases(entry.bundlePath))
        {
            m_lastError = EINVAL;
            return false;
        }

        nlohmann::json document;
        document["version"] = kVersion;
        document["bundle_path"] = entry.bundlePath;
        document["file_sha256"] = entry.fileSha256;
        document["publication"] = entry.publication;
        const auto text = document.dump();

        // Unique per attempt AND per process: a name shared with another writer would make O_EXCL
        // refuse the write instead of protecting it, and a temporary left behind by a SIGKILLed
        // process (which no amount of care can prevent) must not block the next store either
        // (objections 16, 17). We never remove a temporary that is not ours.
        const std::string temporary = m_path + ".tmp." + std::to_string(::getpid()) + "." + std::to_string(++m_attempt);

        const int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0)
        {
            // Nothing was created, so there is nothing to clean up -- and the record already on the
            // path (if any) is untouched, which is the whole point of writing beside it.
            m_lastError = errno;
            return false;
        }

        const auto flush = [this](int descriptor, bool directory)
        {
            return m_io.sync ? m_io.sync(descriptor, directory) : ::fsync(descriptor);
        };

        const auto fail = [this, fd, &temporary](int cause)
        {
            ::close(fd);
            ::unlink(temporary.c_str());
            m_lastError = cause != 0 ? cause : EIO;
            return false;
        };

        // The whole entry, or nothing: write(2) may return short (a signal, a full pipe's
        // equivalent on a filesystem under pressure) and EINTR is not a failure, so neither is
        // treated as one -- a half-written temporary that got renamed would be a malformed record.
        std::size_t written {0};
        while (written < text.size())
        {
            const auto chunk = m_io.write ? m_io.write(fd, text.data() + written, text.size() - written)
                                          : ::write(fd, text.data() + written, text.size() - written);
            if (chunk < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                return fail(errno);
            }
            if (chunk == 0)
            {
                // No progress and no error: refuse rather than spin forever.
                return fail(EIO);
            }
            written += static_cast<std::size_t>(chunk);
        }

        if (flush(fd, /*directory=*/false) != 0)
        {
            return fail(errno);
        }

        // Explicit mode instead of whatever the umask left on the temporary: the record is the
        // service's own file (0640, owned by the user remoted dropped to), and both a restrictive
        // and a permissive umask have to end at the same mode (objection 14).
        if (::fchmod(fd, 0640) != 0)
        {
            return fail(errno);
        }

        if (::close(fd) != 0)
        {
            const int cause = errno;
            ::unlink(temporary.c_str());
            m_lastError = cause != 0 ? cause : EIO;
            return false;
        }

        if (::rename(temporary.c_str(), m_path.c_str()) != 0)
        {
            const int cause = errno;
            ::unlink(temporary.c_str());
            m_lastError = cause != 0 ? cause : EIO;
            return false;
        }

        // The rename is visible now; making it SURVIVE a power loss needs the directory flushed
        // too. If only this fails the record on the path is already the right one, so the write
        // counts as done and the cause stays in lastError() for the caller to say that durability
        // is uncertain (objection 15).
        m_lastError = 0;

        const int directory = ::open(directoryOf(m_path).c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (directory < 0)
        {
            m_lastError = errno;
            return true;
        }

        if (flush(directory, /*directory=*/true) != 0)
        {
            m_lastError = errno != 0 ? errno : EIO;
        }
        ::close(directory);

        return true;
    }

    int CaPublicationRecord::lastError() const noexcept
    {
        return m_lastError;
    }

    const std::string& CaPublicationRecord::path() const noexcept
    {
        return m_path;
    }

    bool ensureRecordDirectory(const std::string& recordPath)
    {
        if (recordPath.empty())
        {
            return false;
        }

        const auto directory = directoryOf(recordPath);
        if (directory == "." || directory == "/")
        {
            return true; // Nothing of ours to create.
        }

        if (::mkdir(directory.c_str(), 0750) == 0)
        {
            // mkdir(2) subtracts the umask, which is not ours to assume, so the mode we mean is set
            // explicitly -- and only on the directory we have just created: one that was already
            // there may have had its mode changed on purpose (a write failure injected for a test,
            // C24), and that must not be undone from here.
            (void)::chmod(directory.c_str(), 0750);
            return true;
        }

        return errno == EEXIST;
    }
} // namespace remoted::http
