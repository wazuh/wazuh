/*
 * Wazuh auth middleware (framework-agnostic)
 * Copyright (C) 2015, Wazuh Inc.
 * July 20, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "keystore.hpp"

#include <charconv>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <sstream>

#include <cerrno>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "cmac.hpp"
#include "hashHelper.h"
#include "loggerHelper.h"

namespace remoted::auth
{

    namespace
    {
        // Not a Keystore member (unlike e.g. RemotedModuleFacade's m_logFn): keeping loggerHelper.h
        // out of keystore.hpp avoids pulling its header-only static functions (which reference a
        // DSO-hidden global) into every other translation unit that includes keystore.hpp -- the
        // module's tests do, and they're linked into a separate binary. Same pattern as
        // deferredForwarder.cpp/authGateway.cpp.
        constexpr auto KEYSTORE_LOGTAG {"wazuh-manager-remoted:keystore"};

        bool isCommentOrBlank(const std::string& line)
        {
            return line.empty() || line[0] == '#' || line[0] == ' ';
        }

        // Matches OS_ReadKeys()'s "removed entry" check: the field right
        // after the id is '#' or '!' for a removed/disabled agent.
        bool isRemovedMarker(const std::string& field)
        {
            return !field.empty() && (field[0] == '#' || field[0] == '!');
        }

        std::vector<std::uint8_t> decodeKey(const std::string& hex)
        {
            if (hex.empty() || hex.size() % 2 != 0)
            {
                return {};
            }
            std::vector<std::uint8_t> bytes(hex.size() / 2);
            if (!fromLowerHex(hex, bytes.data(), bytes.size()))
            {
                return {};
            }
            return bytes;
        }

        // Non-negative integer, fully consuming the field. An agent id is always numeric by
        // design; a client.keys line whose id column isn't can never match a real lookup, so it
        // is skipped at load time rather than kept around as dead weight.
        std::optional<AgentId> parseAgentId(const std::string& id)
        {
            AgentId value = 0;
            const auto [ptr, ec] = std::from_chars(id.data(), id.data() + id.size(), value);
            if (id.empty() || ec != std::errc {} || ptr != id.data() + id.size())
            {
                return std::nullopt;
            }
            return value;
        }

        // Maximum attempts reload() makes to get a stable (non-torn) read of the file before
        // giving up for this call -- see reload()'s doc comment.
        constexpr int kMaxReadAttempts {3};
        constexpr auto kRetryBackoff {std::chrono::milliseconds(20)};

        // Watch every event that can mean "the content behind this path may have changed":
        // IN_MODIFY/IN_CLOSE_WRITE for an in-place rewrite, IN_MOVE_SELF/IN_DELETE_SELF for an
        // atomic replace (rename-over) of the watched file, which also invalidates the watch
        // itself -- see drainInotifyEvents().
        constexpr std::uint32_t kWatchMask {IN_MODIFY | IN_CLOSE_WRITE | IN_MOVE_SELF | IN_DELETE_SELF};

        // Wraps Utils::hashFile() (shared_modules/utils/hashHelper.h): std::nullopt instead of a
        // thrown exception when the file can't be read (e.g. it vanished mid-check).
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
    } // namespace

    Keystore::Keystore(std::string path, int refreshIntervalSeconds)
        : m_path(std::move(path))
        , m_refreshIntervalSeconds(refreshIntervalSeconds > 0 ? refreshIntervalSeconds : kDefaultRefreshIntervalSeconds)
    {
        reload();

        m_inotifyFd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (m_inotifyFd < 0)
        {
            LOGFN_WARN(LogFn {KEYSTORE_LOGTAG},
                       "inotify_init1 failed (errno=%d); client.keys hot-reload falls back to the %d s poll only.",
                       errno,
                       m_refreshIntervalSeconds);
        }
        else
        {
            m_watchDescriptor = inotify_add_watch(m_inotifyFd, m_path.c_str(), kWatchMask);
            if (m_watchDescriptor < 0)
            {
                LOGFN_WARN(LogFn {KEYSTORE_LOGTAG},
                           "Could not watch '%s' for changes (errno=%d); hot-reload falls back to the %d s poll only.",
                           m_path.c_str(),
                           errno,
                           m_refreshIntervalSeconds);
            }
        }

        m_stopEventFd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (m_stopEventFd < 0)
        {
            LOGFN_WARN(LogFn {KEYSTORE_LOGTAG},
                       "eventfd failed (errno=%d); destruction may block up to %d s.",
                       errno,
                       m_refreshIntervalSeconds);
        }

        m_watcherThread = std::thread(&Keystore::watcherLoop, this);
    }

    Keystore::~Keystore()
    {
        if (m_stopEventFd >= 0)
        {
            const std::uint64_t one {1};
            // Best-effort wake-up; if this somehow fails the watcher still exits within
            // m_refreshIntervalSeconds via the poll() timeout below.
            if (write(m_stopEventFd, &one, sizeof(one)) < 0)
            {
                LOGFN_DEBUG1(
                    LogFn {KEYSTORE_LOGTAG}, "Could not signal the client.keys watcher to stop (errno=%d).", errno);
            }
        }

        if (m_watcherThread.joinable())
        {
            m_watcherThread.join();
        }

        if (m_watchDescriptor >= 0 && m_inotifyFd >= 0)
        {
            inotify_rm_watch(m_inotifyFd, m_watchDescriptor);
        }
        if (m_inotifyFd >= 0)
        {
            close(m_inotifyFd);
        }
        if (m_stopEventFd >= 0)
        {
            close(m_stopEventFd);
        }
    }

    void Keystore::watcherLoop()
    {
        LOGFN_DEBUG1(LogFn {KEYSTORE_LOGTAG},
                     "client.keys watcher thread started (refresh interval %d s).",
                     m_refreshIntervalSeconds);

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

            // Doubles as the periodic fallback poll: even with a healthy inotify subscription, we
            // still re-check on this cadence in case an event was ever missed.
            const int timeoutMs = m_refreshIntervalSeconds * 1000;
            const int ready = poll(fds, static_cast<nfds_t>(nfds), timeoutMs);

            if (ready < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                LOGFN_WARN(LogFn {KEYSTORE_LOGTAG}, "poll() on the client.keys watcher failed (errno=%d).", errno);
                std::this_thread::sleep_for(std::chrono::seconds(m_refreshIntervalSeconds));
                continue;
            }

            if (stopIdx >= 0 && (fds[stopIdx].revents & POLLIN))
            {
                break; // cooperative shutdown
            }

            if (inotifyIdx >= 0 && (fds[inotifyIdx].revents & POLLIN))
            {
                drainInotifyEvents();
            }

            if (fileLooksChanged())
            {
                reload();
            }
        }

        LOGFN_DEBUG1(LogFn {KEYSTORE_LOGTAG}, "client.keys watcher thread stopped.");
    }

    void Keystore::drainInotifyEvents()
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
                break; // EAGAIN (nothing left, non-blocking fd) or a real error -- stop draining either way
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

        // The file was replaced (e.g. an atomic rename-over by enrollment tooling) -- the watch
        // descriptor now points nowhere useful. Re-arm it on the same path, which resolves to
        // whatever is there now.
        if (m_watchDescriptor >= 0)
        {
            inotify_rm_watch(m_inotifyFd, m_watchDescriptor); // likely already gone; errors are harmless here
        }
        m_watchDescriptor = inotify_add_watch(m_inotifyFd, m_path.c_str(), kWatchMask);
        if (m_watchDescriptor < 0)
        {
            LOGFN_WARN(LogFn {KEYSTORE_LOGTAG},
                       "Could not re-arm the client.keys watch after it was invalidated (errno=%d); "
                       "falling back to the %d s poll only.",
                       errno,
                       m_refreshIntervalSeconds);
        }
        else
        {
            LOGFN_DEBUG1(LogFn {KEYSTORE_LOGTAG}, "client.keys watch re-armed after the file was replaced.");
        }
    }

    bool Keystore::fileLooksChanged()
    {
        std::lock_guard<std::mutex> lock(m_reloadMutex);

        const auto currentHash = hashFileOrNullopt(m_path);
        if (!currentHash)
        {
            return false; // transiently unreachable (e.g. mid-rename); the next cycle will retry
        }
        return !m_hasBaseline || *currentHash != m_lastHash;
    }

    int Keystore::reload()
    {
        std::lock_guard<std::mutex> reloadLock(m_reloadMutex);

        for (int attempt = 0; attempt < kMaxReadAttempts; ++attempt)
        {
            const auto preHash = hashFileOrNullopt(m_path);
            if (!preHash)
            {
                return -1; // missing/unreadable -- not a torn-read case, nothing to retry
            }

            std::ifstream file(m_path);
            if (!file.is_open())
            {
                return -1;
            }

            std::unordered_map<AgentId, std::vector<std::uint8_t>> loaded;
            std::string line;
            int count = 0;

            while (std::getline(file, line))
            {
                if (isCommentOrBlank(line))
                {
                    continue;
                }

                std::istringstream tokens(line);
                std::string id, name, ip, key;
                if (!(tokens >> id >> name >> ip >> key))
                {
                    continue; // malformed line: fewer than 4 fields
                }

                if (isRemovedMarker(name))
                {
                    continue; // removed/disabled entry -- same as OS_ReadKeys()
                }

                const auto agentId = parseAgentId(id);
                if (!agentId)
                {
                    // TODO: Log warning: "client.keys line %d: agent id '%s' is not a non-negative integer, skipping"
                    continue; // id column isn't numeric -- can never match a real lookup
                }

                loaded[*agentId] = decodeKey(key);
                ++count;
            }
            file.close();

            // Bracket the parse with a second hash: if the file's content changed at all while we
            // were reading it -- even a same-second rewrite that mtime alone wouldn't catch --
            // discard this attempt rather than adopt a table built from a possibly torn read.
            const auto postHash = hashFileOrNullopt(m_path);

            if (postHash && *postHash == *preHash)
            {
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    m_keys = std::move(loaded);
                }
                m_hasBaseline = true;
                m_lastHash = *preHash;
                return count;
            }

            LOGFN_DEBUG1(LogFn {KEYSTORE_LOGTAG},
                         "client.keys changed while reloading (attempt %d/%d), retrying.",
                         attempt + 1,
                         kMaxReadAttempts);
            if (attempt + 1 < kMaxReadAttempts)
            {
                std::this_thread::sleep_for(kRetryBackoff);
            }
        }

        LOGFN_WARN(LogFn {KEYSTORE_LOGTAG},
                   "client.keys kept changing across %d attempts; keeping the previous table.",
                   kMaxReadAttempts);
        return -1;
    }

    std::optional<std::vector<std::uint8_t>> Keystore::keyFor(AgentId agentId) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it = m_keys.find(agentId);
        if (it == m_keys.end())
        {
            return std::nullopt;
        }
        return it->second;
    }

} // namespace remoted::auth
