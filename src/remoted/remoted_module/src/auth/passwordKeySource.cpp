/*
 * Wazuh auth middleware (framework-agnostic)
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "passwordKeySource.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>

#include <cctype>
#include <cerrno>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "hashHelper.h"
#include "jwt/enrollKeyDerivation.hpp"
#include "loggerHelper.h"

namespace remoted::auth
{

    namespace
    {
        // Same rationale as keystore.cpp: keeping loggerHelper.h out of the header avoids pulling
        // its DSO-hidden global into every translation unit that includes passwordKeySource.hpp.
        constexpr auto PASSWORD_KEY_SOURCE_LOGTAG {"wazuh-manager-remoted:passwordKeySource"};

        const LogFn& logFn()
        {
            static const LogFn instance {PASSWORD_KEY_SOURCE_LOGTAG};
            return instance;
        }

        constexpr int kMaxReadAttempts {3};
        constexpr auto kRetryBackoff {std::chrono::milliseconds(20)};

        constexpr std::uint32_t kWatchMask {IN_MODIFY | IN_CLOSE_WRITE | IN_MOVE_SELF | IN_DELETE_SELF};

        std::optional<std::vector<unsigned char>> hashFileOrNullopt(const std::string& path)
        {
            try
            {
                return Utils::hashFile(path);
            }
            catch (const std::exception&)
            {
                return std::nullopt;
            }
        }

        /// Maximum bytes read for the first line, matching authd's read_password_line() buffer
        /// (4096 + 1 for the null terminator) exactly.
        constexpr std::size_t kMaxLineBytes {4096};

        /**
         * @brief Read and validate the first line of the password file, byte-matching authd's
         *        own read_password_line() (os_auth/src/auth.c).
         *
         * @return The password string on success, std::nullopt on any of: file not open, no
         *         line read, line filled the buffer without a trailing newline (too long),
         *         length <= 2 after stripping trailing '\r'/'\n', or the remainder is entirely
         *         whitespace.
         */
        std::optional<std::string> readPasswordLine(const std::string& path)
        {
            std::FILE* fp = std::fopen(path.c_str(), "r");
            if (!fp)
            {
                return std::nullopt;
            }

            std::vector<char> buf(kMaxLineBytes + 1);
            const bool gotLine = std::fgets(buf.data(), static_cast<int>(buf.size()), fp) != nullptr;
            std::fclose(fp);

            if (!gotLine)
            {
                return std::nullopt;
            }

            std::size_t len = std::strlen(buf.data());

            // fgets filled the buffer without a newline: the line exceeds the maximum length.
            if (len == kMaxLineBytes && buf[len - 1] != '\n')
            {
                return std::nullopt;
            }

            while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
            {
                buf[--len] = '\0';
            }

            if (len <= 2)
            {
                return std::nullopt;
            }

            bool allSpace = true;
            for (std::size_t i = 0; i < len; ++i)
            {
                if (!std::isspace(static_cast<unsigned char>(buf[i])))
                {
                    allSpace = false;
                    break;
                }
            }
            if (allSpace)
            {
                return std::nullopt;
            }

            return std::string(buf.data(), len);
        }

    } // namespace

    PasswordKeySource::PasswordKeySource(std::string path, int refreshIntervalSeconds)
        : m_path(std::move(path))
        , m_refreshIntervalSeconds(refreshIntervalSeconds > 0 ? refreshIntervalSeconds : kDefaultRefreshIntervalSeconds)
    {
        // Report the initial state unconditionally: if Password mode is selected but this file
        // isn't readable yet (e.g. not synced from the master to a worker), every enrollment
        // attempt will be rejected 401 until it becomes available -- otherwise invisible.
        if (reload())
        {
            LOGFN_INFO(logFn(), "Enrollment password loaded from '%s'.", m_path.c_str());
        }
        else
        {
            LOGFN_WARN(logFn(),
                       "Could not load a usable enrollment password from '%s' at startup; "
                       "Password-mode enrollment requests will be rejected until it is available.",
                       m_path.c_str());
        }

        m_inotifyFd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (m_inotifyFd < 0)
        {
            LOGFN_WARN(logFn(),
                       "inotify_init1 failed (errno=%d); authd.pass hot-reload falls back to the %d s poll only.",
                       errno,
                       m_refreshIntervalSeconds);
        }
        else
        {
            m_watchDescriptor = inotify_add_watch(m_inotifyFd, m_path.c_str(), kWatchMask);
            if (m_watchDescriptor < 0)
            {
                LOGFN_WARN(logFn(),
                           "Could not watch '%s' for changes (errno=%d); hot-reload falls back to the %d s poll only.",
                           m_path.c_str(),
                           errno,
                           m_refreshIntervalSeconds);
            }
        }

        m_stopEventFd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (m_stopEventFd < 0)
        {
            LOGFN_WARN(logFn(),
                       "eventfd failed (errno=%d); destruction may block up to %d s.",
                       errno,
                       m_refreshIntervalSeconds);
        }

        try
        {
            m_watcherThread = std::thread(&PasswordKeySource::watcherLoop, this);
        }
        catch (...)
        {
            closeWatchFds();
            throw;
        }
    }

    void PasswordKeySource::closeWatchFds() noexcept
    {
        if (m_watchDescriptor >= 0 && m_inotifyFd >= 0)
        {
            inotify_rm_watch(m_inotifyFd, m_watchDescriptor);
            m_watchDescriptor = -1;
        }
        if (m_inotifyFd >= 0)
        {
            close(m_inotifyFd);
            m_inotifyFd = -1;
        }
        if (m_stopEventFd >= 0)
        {
            close(m_stopEventFd);
            m_stopEventFd = -1;
        }
    }

    PasswordKeySource::~PasswordKeySource()
    {
        try
        {
            // Set unconditionally, BEFORE the eventfd write: this is the only reliable stop signal
            // when eventfd() failed at construction (m_stopEventFd stays -1) and there is no fd to
            // wake poll() early. In that case the loop still notices this within one more
            // poll() timeout (at most m_refreshIntervalSeconds), rather than never.
            m_stopping.store(true);

            if (m_stopEventFd >= 0)
            {
                const std::uint64_t one {1};
                if (write(m_stopEventFd, &one, sizeof(one)) < 0)
                {
                    LOGFN_DEBUG1(logFn(), "Could not signal the authd.pass watcher to stop (errno=%d).", errno);
                }
            }

            if (m_watcherThread.joinable())
            {
                m_watcherThread.join();
            }
        }
        catch (...) // NOLINT(bugprone-empty-catch)
        {
        }

        closeWatchFds();
    }

    void PasswordKeySource::watcherLoop()
    {
        try
        {
            watcherLoopBody();
        }
        catch (const std::exception& e)
        {
            LOGFN_ERROR(logFn(),
                        "The authd.pass watcher thread stopped on an unexpected exception: %s. The enrollment "
                        "password will not be hot-reloaded until wazuh-remoted is restarted.",
                        e.what());
        }
        catch (...)
        {
            LOGFN_ERROR(logFn(),
                        "The authd.pass watcher thread stopped on a non-standard exception. The enrollment "
                        "password will not be hot-reloaded until wazuh-remoted is restarted.");
        }
    }

    void PasswordKeySource::watcherLoopBody()
    {
        LOGFN_DEBUG1(logFn(), "authd.pass watcher thread started (refresh interval %d s).", m_refreshIntervalSeconds);

        while (true)
        {
            struct pollfd fds[2] {};
            int nfds = 0;
            int inotifyIdx = -1;
            int stopIdx = -1;

            if (m_inotifyFd >= 0)
            {
                inotifyIdx = nfds;
                fds[nfds].fd = m_inotifyFd;
                fds[nfds].events = POLLIN;
                ++nfds;
            }
            if (m_stopEventFd >= 0)
            {
                stopIdx = nfds;
                fds[nfds].fd = m_stopEventFd;
                fds[nfds].events = POLLIN;
                ++nfds;
            }

            const int timeoutMs = m_refreshIntervalSeconds * 1000;
            const int ready = poll(fds, static_cast<nfds_t>(nfds), timeoutMs);

            if (ready < 0)
            {
                if (errno == EINTR)
                {
                    // Checked here too, not just after a real poll() failure below: under a
                    // persistent signal storm, every poll() call could keep returning EINTR
                    // forever, and this `continue` would otherwise loop back to poll() again
                    // without ever reaching the m_stopping checks further down -- the only way
                    // this thread would then ever notice a pending stop is if the signal storm
                    // happens to end at the exact moment a poll() call completes normally.
                    if (m_stopping.load())
                    {
                        break;
                    }
                    continue;
                }
                if (m_stopping.load())
                {
                    break;
                }
                LOGFN_WARN(logFn(), "poll() on the authd.pass watcher failed (errno=%d).", errno);
                std::this_thread::sleep_for(std::chrono::seconds(m_refreshIntervalSeconds));
                continue;
            }

            // Checked on EVERY wakeup, not just the eventfd-signaled one: this is the fallback
            // path when eventfd() failed at construction (m_stopEventFd stays -1, stopIdx stays
            // -1 below) -- poll() then has no fd to wake it early and just times out every
            // m_refreshIntervalSeconds, which is enough to notice this flag within one more cycle.
            if (m_stopping.load())
            {
                break;
            }

            if (stopIdx >= 0 && (fds[stopIdx].revents & POLLIN))
            {
                break;
            }

            if (inotifyIdx >= 0 && (fds[inotifyIdx].revents & POLLIN))
            {
                drainInotifyEvents();
            }

            if (fileLooksChanged())
            {
                if (reload())
                {
                    LOGFN_INFO(logFn(), "Enrollment password reloaded from '%s'.", m_path.c_str());
                }
                else if (const auto d = m_unreadableThrottle.record())
                {
                    LOGFN_WARN(logFn(),
                               "'%s' is not readable or its content is invalid (errno=%d); Password-mode "
                               "enrollment requests will be rejected. %llu failed attempt(s) in the last %d s.",
                               m_path.c_str(),
                               errno,
                               static_cast<unsigned long long>(d.total),
                               remoted::common::LogThrottle::kDefaultWindowSeconds);
                }
            }
        }

        LOGFN_DEBUG1(logFn(), "authd.pass watcher thread stopped.");
    }

    void PasswordKeySource::drainInotifyEvents()
    {
        if (m_inotifyFd < 0)
        {
            return;
        }

        alignas(struct inotify_event) char buffer[4096];
        bool watchInvalidated = false;

        while (true)
        {
            const ssize_t bytesRead = read(m_inotifyFd, buffer, sizeof(buffer));
            if (bytesRead <= 0)
            {
                break;
            }

            ssize_t offset = 0;
            while (offset < bytesRead)
            {
                const auto* event = reinterpret_cast<const struct inotify_event*>(buffer + offset);
                if (event->mask & (IN_IGNORED | IN_MOVE_SELF | IN_DELETE_SELF))
                {
                    watchInvalidated = true;
                }
                offset += static_cast<ssize_t>(sizeof(struct inotify_event) + event->len);
            }
        }

        if (!watchInvalidated)
        {
            return;
        }

        if (m_watchDescriptor >= 0)
        {
            inotify_rm_watch(m_inotifyFd, m_watchDescriptor);
        }
        m_watchDescriptor = inotify_add_watch(m_inotifyFd, m_path.c_str(), kWatchMask);
        if (m_watchDescriptor < 0)
        {
            LOGFN_WARN(logFn(),
                       "Could not re-arm the authd.pass watch after it was invalidated (errno=%d); "
                       "falling back to the %d s poll only.",
                       errno,
                       m_refreshIntervalSeconds);
        }
        else
        {
            LOGFN_DEBUG1(logFn(), "authd.pass watch re-armed after the file was replaced.");
        }
    }

    bool PasswordKeySource::fileLooksChanged()
    {
        std::lock_guard<std::mutex> lock(m_reloadMutex);

        const auto currentHash = hashFileOrNullopt(m_path);
        if (!currentHash)
        {
            // Unlike Keystore (whose backing file is expected to always exist once created),
            // authd.pass going missing/unreadable is an expected admin action -- revoking
            // Password-mode enrollment -- and must invalidate any cached key right away rather
            // than waiting for the file to reappear. reload() below clears m_hasBaseline in this
            // same case so a later reload isn't skipped just because the file comes back with
            // byte-identical content.
            return true;
        }
        return !m_hasBaseline || *currentHash != m_lastHash;
    }

    bool PasswordKeySource::reload()
    {
        std::lock_guard<std::mutex> reloadLock(m_reloadMutex);

        for (int attempt = 0; attempt < kMaxReadAttempts; ++attempt)
        {
            const auto preHash = hashFileOrNullopt(m_path);
            if (!preHash)
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_derivedKey.reset();
                // Clear the baseline: if the file later reappears with content that hashes the
                // same as what we saw before it vanished, fileLooksChanged() must still treat
                // that as a change (there's no other signal that the key needs re-deriving).
                m_hasBaseline = false;
                return false;
            }

            auto password = readPasswordLine(m_path);

            const auto postHash = hashFileOrNullopt(m_path);
            if (postHash && *postHash == *preHash)
            {
                if (!password)
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    m_derivedKey.reset();
                    m_hasBaseline = true;
                    m_lastHash = *preHash;
                    return false;
                }

                // The one HKDF construction the agent shares (jwt/enrollKeyDerivation.hpp): see the
                // Agent enrollment chapter of remoted_module/README.md for the known-answer vector.
                auto derived = jwt_profile::v1::enroll::deriveEnrollKey(*password);
                if (!derived)
                {
                    // Global/permanent (OpenSSL HKDF provider failure), not per-attempt -- log loudly
                    // and fail closed: no key means every Password-mode enrollment is rejected.
                    LOGFN_ERROR(
                        logFn(), "Could not derive the enrollment key from '%s' (HKDF unavailable).", m_path.c_str());
                    std::lock_guard<std::mutex> lock(m_mutex);
                    m_derivedKey.reset();
                    m_hasBaseline = true;
                    m_lastHash = *preHash;
                    return false;
                }

                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    m_derivedKey = std::move(derived);
                }
                m_hasBaseline = true;
                m_lastHash = *preHash;
                return true;
            }

            LOGFN_DEBUG1(logFn(),
                         "authd.pass changed while reloading (attempt %d/%d), retrying.",
                         attempt + 1,
                         kMaxReadAttempts);
            if (attempt + 1 < kMaxReadAttempts)
            {
                std::this_thread::sleep_for(kRetryBackoff);
            }
        }

        LOGFN_WARN(logFn(), "authd.pass kept changing across %d attempts; keeping the previous key.", kMaxReadAttempts);
        return static_cast<bool>(currentKey());
    }

    std::optional<jwt_profile::v1::SecureBytes> PasswordKeySource::currentKey() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_derivedKey)
        {
            return std::nullopt;
        }
        return jwt_profile::v1::SecureBytes(m_derivedKey->data(), m_derivedKey->size()); // a wiped-on-destroy copy
    }

} // namespace remoted::auth
