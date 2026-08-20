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

        // One shared instance instead of a `LogFn {TAG}` temporary per log call: LogFn holds a
        // std::string and this tag is well past the SSO threshold, so the temporary form
        // heap-allocates on every single line. A function-local static also avoids the
        // static-initialization-order trap a namespace-scope object would have, and cannot throw
        // from ~Keystore() (which is implicitly noexcept).
        const LogFn& logFn()
        {
            static const LogFn instance {KEYSTORE_LOGTAG};
            return instance;
        }

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
        // Report the initial load unconditionally: an unreadable client.keys at startup means every
        // agent request will be rejected as "unknown agent", which without this line was completely
        // invisible -- the operator saw universal 401s and nothing explaining them.
        const int loaded = reload();
        if (loaded < 0)
        {
            LOGFN_WARN(logFn(),
                       "Could not read '%s' at startup (errno=%d); every agent request will be rejected as unknown "
                       "until the file becomes readable.",
                       m_path.c_str(),
                       errno);
        }
        else
        {
            LOGFN_INFO(logFn(), "Loaded %d agent key(s) from '%s'.", loaded, m_path.c_str());
        }

        m_inotifyFd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (m_inotifyFd < 0)
        {
            LOGFN_WARN(logFn(),
                       "inotify_init1 failed (errno=%d); client.keys hot-reload falls back to the %d s poll only.",
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
            m_watcherThread = std::thread(&Keystore::watcherLoop, this);
        }
        catch (...)
        {
            // A constructor that throws never runs the destructor, so the fds opened above would
            // leak. Close them, then let the failure propagate (the facade catches it and retries
            // on the next heartbeat).
            closeWatchFds();
            throw;
        }
    }

    void Keystore::closeWatchFds() noexcept
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

    Keystore::~Keystore()
    {
        // A destructor is implicitly noexcept: anything escaping here terminates the process. The
        // join() below can throw std::system_error, and the logging call allocates.
        try
        {
            if (m_stopEventFd >= 0)
            {
                const std::uint64_t one {1};
                // Best-effort wake-up; if this somehow fails the watcher still exits within
                // m_refreshIntervalSeconds via the poll() timeout below.
                if (write(m_stopEventFd, &one, sizeof(one)) < 0)
                {
                    LOGFN_DEBUG1(logFn(), "Could not signal the client.keys watcher to stop (errno=%d).", errno);
                }
            }

            if (m_watcherThread.joinable())
            {
                m_watcherThread.join();
            }
        }
        catch (...) // NOLINT(bugprone-empty-catch) -- see above; nothing useful is left to do here
        {
        }

        closeWatchFds();
    }

    void Keystore::watcherLoop()
    {
        // Exception barrier for the thread body. Same rationale as the downstream UDS client's I/O
        // threads (see downstream/asioUdsHttpClient.cpp): nothing below is expected to throw, but
        // reload() allocates freely (ifstream, std::string, istringstream, unordered_map, vector,
        // plus the file hash), and an exception escaping a bare std::thread terminates the whole
        // remoted daemon rather than just this thread.
        try
        {
            watcherLoopBody();
        }
        catch (const std::exception& e)
        {
            LOGFN_ERROR(logFn(),
                        "The client.keys watcher thread stopped on an unexpected exception: %s. Agent keys will "
                        "not be hot-reloaded until wazuh-remoted is restarted.",
                        e.what());
        }
        catch (...)
        {
            LOGFN_ERROR(logFn(),
                        "The client.keys watcher thread stopped on a non-standard exception. Agent keys will not "
                        "be hot-reloaded until wazuh-remoted is restarted.");
        }
    }

    void Keystore::watcherLoopBody()
    {
        LOGFN_DEBUG1(logFn(), "client.keys watcher thread started (refresh interval %d s).", m_refreshIntervalSeconds);

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
                LOGFN_WARN(logFn(), "poll() on the client.keys watcher failed (errno=%d).", errno);
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
                const int loaded = reload();
                if (loaded >= 0)
                {
                    // Unthrottled on purpose: reload() only runs here when the content hash actually
                    // changed, i.e. an operator enrolled or removed an agent. That is a real event
                    // and worth one line -- it is not driven by request traffic.
                    LOGFN_INFO(logFn(), "Reloaded %d agent key(s) from '%s'.", loaded, m_path.c_str());
                }
                else if (loaded == kReloadUnreadable)
                {
                    // Throttled: the watcher retries on every tick (10 s by default), so an
                    // unreadable file would otherwise print thousands of identical lines a day.
                    if (const auto d = m_unreadableThrottle.record())
                    {
                        LOGFN_WARN(logFn(),
                                   "'%s' is not readable (errno=%d); keeping the previously loaded keys. %llu failed "
                                   "attempt(s) in the last %d s.",
                                   m_path.c_str(),
                                   errno,
                                   static_cast<unsigned long long>(d.total),
                                   remoted::common::LogThrottle::kDefaultWindowSeconds);
                    }
                }
                // kReloadUnstable already logged its own warning inside reload().
            }
        }

        LOGFN_DEBUG1(logFn(), "client.keys watcher thread stopped.");
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
            LOGFN_WARN(logFn(),
                       "Could not re-arm the client.keys watch after it was invalidated (errno=%d); "
                       "falling back to the %d s poll only.",
                       errno,
                       m_refreshIntervalSeconds);
        }
        else
        {
            LOGFN_DEBUG1(logFn(), "client.keys watch re-armed after the file was replaced.");
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
                // Missing/unreadable, not a torn read -- nothing to retry. Deliberately NOT logged
                // here: reload() is called both once at startup and repeatedly by the watcher, which
                // need different messages and different throttling. Both call sites report it.
                return kReloadUnreadable;
            }

            std::ifstream file(m_path);
            if (!file.is_open())
            {
                return kReloadUnreadable;
            }

            std::unordered_map<AgentId, std::vector<std::uint8_t>> loaded;
            std::string line;
            int count = 0;
            int lineNumber = 0;

            while (std::getline(file, line))
            {
                ++lineNumber;

                if (isCommentOrBlank(line))
                {
                    continue;
                }

                std::istringstream tokens(line);
                std::string id, name, ip, key;
                if (!(tokens >> id >> name >> ip >> key))
                {
                    LOGFN_DEBUG1(logFn(), "client.keys line %d has fewer than 4 fields; skipping.", lineNumber);
                    continue; // malformed line: fewer than 4 fields
                }

                if (isRemovedMarker(name))
                {
                    continue; // removed/disabled entry -- same as OS_ReadKeys()
                }

                const auto agentId = parseAgentId(id);
                if (!agentId)
                {
                    LOGFN_DEBUG1(logFn(),
                                 "client.keys line %d: agent id '%s' is not a non-negative integer; skipping.",
                                 lineNumber,
                                 id.c_str());
                    continue; // id column isn't numeric -- can never match a real lookup
                }

                auto decoded = decodeKey(key);
                if (decoded.empty())
                {
                    // Store the empty key anyway: keyFor() returning an empty vector (rather than
                    // nullopt) is what lets the auth middleware answer the more precise MissingKey
                    // instead of UnknownAgent. But do NOT count it as loaded -- it cannot
                    // authenticate anything, and counting it made a broken entry look healthy.
                    LOGFN_WARN(logFn(),
                               "client.keys line %d: the key for agent %u does not decode to a valid AES key; that "
                               "agent's requests will be rejected. Re-enroll it.",
                               lineNumber,
                               *agentId);
                    loaded[*agentId] = std::move(decoded);
                    continue;
                }

                loaded[*agentId] = std::move(decoded);
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

            LOGFN_DEBUG1(logFn(),
                         "client.keys changed while reloading (attempt %d/%d), retrying.",
                         attempt + 1,
                         kMaxReadAttempts);
            if (attempt + 1 < kMaxReadAttempts)
            {
                std::this_thread::sleep_for(kRetryBackoff);
            }
        }

        LOGFN_WARN(
            logFn(), "client.keys kept changing across %d attempts; keeping the previous table.", kMaxReadAttempts);
        return kReloadUnstable;
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
