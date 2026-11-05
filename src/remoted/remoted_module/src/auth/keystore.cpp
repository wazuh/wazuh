/*
 * Wazuh auth middleware (framework-agnostic)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "keystore.hpp"

#include <algorithm>
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

#include "hashHelper.h"
#include "jwt/jwtKeyDecoder.hpp"
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
        // "client-keys", not "keystore": this is the agent registry (client.keys), and the manager's
        // secrets keystore (wazuh-manager-keystore) is a different thing an operator must not confuse.
        constexpr auto KEYSTORE_LOGTAG {"wazuh-manager-remoted:client-keys"};

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

        // Exactly the key shape of the wazuh-agent+jwt profile: 64 lowercase hex chars -> 32 bytes.
        // Anything else (uppercase, odd lengths, non-hex) decodes to an EMPTY key, so the agent is answered MissingKey
        // -- "re-enroll"
        // -- instead of failing signature checks forever.
        std::vector<std::uint8_t> decodeKey(const std::string& hex)
        {
            const auto key = jwt_profile::v1::JwtKeyDecoder::decode(hex);
            if (!key)
            {
                return {};
            }
            return std::vector<std::uint8_t>(key->data(), key->data() + key->size());
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

        // The three columns a lookup needs, parsed the one way reload() and upsert() share (the
        // header promises an adopted credential is parsed like a file line). Each column is
        // reported on its own so the callers can say which one failed: reload() logs and counts per
        // line, upsert() stores nothing unless all three parse.
        struct ParsedColumns
        {
            std::optional<AgentId> id;
            decltype(AddressRule::parse(std::string {})) address;
            std::vector<std::uint8_t> key; ///< Empty when the key column does not decode.
        };

        ParsedColumns parseColumns(const std::string& id, const std::string& ip, const std::string& key)
        {
            return ParsedColumns {parseAgentId(id), AddressRule::parse(ip), decodeKey(key)};
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

    Keystore::Keystore(std::string path, int refreshIntervalSeconds, Clock clock)
        : m_path(std::move(path))
        , m_refreshIntervalSeconds(refreshIntervalSeconds > 0 ? refreshIntervalSeconds : kDefaultRefreshIntervalSeconds)
        , m_clock(clock ? std::move(clock) : Clock {[] { return std::chrono::steady_clock::now(); }})
    {
        // Report the initial load unconditionally: an unreadable client.keys at startup means every
        // agent request will be rejected as "unknown agent", which without this line was completely
        // invisible -- the operator saw universal 401s and nothing explaining them.
        const int loaded = reload();
        if (loaded < 0)
        {
            LOGFN_ERROR(logFn(),
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
            // Set unconditionally, BEFORE the eventfd write: the only reliable stop signal when
            // eventfd() failed at construction (m_stopEventFd stays -1, so there's no fd to wake
            // poll() early). In that case the loop still notices this within one more poll()
            // timeout (at most m_refreshIntervalSeconds) instead of never -- see watcherLoopBody().
            m_stopping.store(true);

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
                LOGFN_WARN(logFn(), "poll() on the client.keys watcher failed (errno=%d).", errno);
                std::this_thread::sleep_for(std::chrono::seconds(m_refreshIntervalSeconds));
                continue;
            }

            // Checked on EVERY wakeup, not just the eventfd-signaled one: this is the fallback
            // path when eventfd() failed at construction (m_stopEventFd stays -1, stopIdx stays -1
            // below) -- poll() then has no fd to wake it early and just times out every
            // m_refreshIntervalSeconds, which is enough to notice this flag within one more cycle.
            if (m_stopping.load())
            {
                break;
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
                                   "attempt(s) %s.",
                                   m_path.c_str(),
                                   errno,
                                   static_cast<unsigned long long>(d.total),
                                   d.period().c_str());
                    }
                }
                // kReloadUnstable already logged its own warning inside reload().
            }

            // The grace bounds how long an adopted key is KEPT, not only how long lookup() honors
            // it: on a quiet manager (no reload, no adoption) nothing else would drop an expired
            // entry or count it. Reading the level deliberately does not.
            std::vector<ExpiredAdoption> expired;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                expired = expireAdoptedLocked(m_clock());
            }
            reportExpired(expired);
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
                m_reloadFailuresTotal.fetch_add(1, std::memory_order_relaxed);
                m_lastLoadOk.store(false, std::memory_order_relaxed);
                return kReloadUnreadable;
            }

            std::ifstream file(m_path);
            if (!file.is_open())
            {
                m_reloadFailuresTotal.fetch_add(1, std::memory_order_relaxed);
                m_lastLoadOk.store(false, std::memory_order_relaxed);
                return kReloadUnreadable;
            }

            std::unordered_map<AgentId, AgentEntry> loaded;
            std::string line;
            int count = 0;
            // Lines the load could not use. Comments, blanks and deliberately removed entries
            // are NOT counted here: those are normal states, not defects an operator must fix.
            int skipped = 0;
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
                    ++skipped;
                    continue; // malformed line: fewer than 4 fields
                }

                if (isRemovedMarker(name))
                {
                    continue; // removed/disabled entry -- same as OS_ReadKeys()
                }

                auto columns = parseColumns(id, ip, key);
                const auto& agentId = columns.id;
                if (!agentId)
                {
                    LOGFN_DEBUG1(logFn(),
                                 "client.keys line %d: agent id '%s' is not a non-negative integer; skipping.",
                                 lineNumber,
                                 id.c_str());
                    ++skipped;
                    continue; // id column isn't numeric -- can never match a real lookup
                }

                // Skip the line rather than load it unrestricted: an ip column that does not parse
                // would otherwise turn a fixed-address registration into one that accepts any peer.
                auto& addressRule = columns.address;
                if (!addressRule)
                {
                    LOGFN_WARN(logFn(),
                               "client.keys line %d: the address '%s' registered for agent %u is not a valid address "
                               "or range; that agent's requests will be rejected until it is fixed.",
                               lineNumber,
                               ip.c_str(),
                               *agentId);
                    ++skipped;
                    continue;
                }

                auto& decoded = columns.key;
                if (decoded.empty())
                {
                    // Store the empty key anyway: lookup() returning an empty key (rather than
                    // nullopt) is what lets the auth middleware answer the more precise MissingKey
                    // instead of UnknownAgent. But do NOT count it as loaded -- it cannot
                    // authenticate anything, and counting it made a broken entry look healthy.
                    LOGFN_WARN(logFn(),
                               "client.keys line %d: the key for agent %u does not decode to a valid 32-byte key (64 "
                               "lowercase hex chars); that "
                               "agent's requests will be rejected. Re-enroll it.",
                               lineNumber,
                               *agentId);
                    loaded.insert_or_assign(*agentId, AgentEntry {std::move(decoded), std::move(*addressRule)});
                    ++skipped;
                    continue;
                }

                loaded.insert_or_assign(*agentId, AgentEntry {std::move(decoded), std::move(*addressRule)});
                ++count;
            }
            file.close();

            // Bracket the parse with a second hash: if the file's content changed at all while we
            // were reading it -- even a same-second rewrite that mtime alone wouldn't catch --
            // discard this attempt rather than adopt a table built from a possibly torn read.
            const auto postHash = hashFileOrNullopt(m_path);

            if (postHash && *postHash == *preHash)
            {
                std::vector<ExpiredAdoption> expired;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    m_keys = std::move(loaded);
                    // An adopted entry is retired as soon as the file is no longer behind it:
                    //  - it carries the adopted key (converged; only the key is compared);
                    //  - it no longer carries an id it has carried since the adoption (removed);
                    //  - it carries a key the adoption does not supersede (rotated elsewhere: keeping
                    //    the adopted key first in lookup() would refuse the current one) -- unless
                    //    the entry is saturated, when an unknown key proves nothing.
                    // A file without the id that never had it, or still on a superseded key, is
                    // behind: the entry stays. Reconciled before expiring, so a late convergence is
                    // not an expiry.
                    for (auto it = m_pending.begin(); it != m_pending.end();)
                    {
                        auto& pending = it->second;
                        const auto inFile = m_keys.find(it->first);
                        const char* retiredBecause = nullptr;
                        if (inFile == m_keys.end())
                        {
                            retiredBecause = pending.idSeenInFile ? "entry removed" : nullptr;
                        }
                        else if (inFile->second.key == pending.entry.key)
                        {
                            LOGFN_DEBUG1(logFn(), "client.keys now carries the key adopted for agent %u.", it->first);
                            it = m_pending.erase(it);
                            continue;
                        }
                        else
                        {
                            pending.idSeenInFile = true;
                            const auto& superseded = pending.supersededKeys;
                            const bool behind =
                                std::find(superseded.begin(), superseded.end(), inFile->second.key) != superseded.end();
                            retiredBecause = behind || pending.saturated ? nullptr : "another key";
                        }

                        if (retiredBecause != nullptr)
                        {
                            LOGFN_DEBUG1(logFn(),
                                         "client.keys moved past the key adopted for agent %u (%s); the file's "
                                         "entry takes over.",
                                         it->first,
                                         retiredBecause);
                            it = m_pending.erase(it);
                        }
                        else
                        {
                            ++it;
                        }
                    }
                    expired = expireAdoptedLocked(m_clock());
                }
                reportExpired(expired);
                m_hasBaseline = true;
                m_lastHash = *preHash;
                // Health counters (the remoted.auth.keystore.* pulls): the LEVEL tracks what the
                // table now holds, the total answers "did the hot-reload actually pick my
                // re-enrolls up".
                m_agentsLoaded.store(static_cast<std::size_t>(count), std::memory_order_relaxed);
                m_entriesSkipped.store(static_cast<std::size_t>(skipped), std::memory_order_relaxed);
                m_reloadsTotal.fetch_add(1, std::memory_order_relaxed);
                m_lastLoadOk.store(true, std::memory_order_relaxed);
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
        m_reloadFailuresTotal.fetch_add(1, std::memory_order_relaxed);
        m_lastLoadOk.store(false, std::memory_order_relaxed);
        return kReloadUnstable;
    }

    bool Keystore::upsert(const std::string& id, const std::string& ip, const std::string& keyHex)
    {
        auto columns = parseColumns(id, ip, keyHex);
        const auto& agentId = columns.id;
        auto& addressRule = columns.address;
        auto& decoded = columns.key;
        if (!agentId || !addressRule || decoded.empty())
        {
            return false; // Unlike reload(), an entry that cannot authenticate is not worth adopting.
        }

        const auto now = m_clock();
        std::vector<ExpiredAdoption> expired;
        std::unique_lock<std::mutex> lock(m_mutex);
        m_adoptionsTotal.fetch_add(1, std::memory_order_relaxed);
        // authd's writer pass can land before this call (it is signaled before the reply is built):
        // the file already serves the key, so a pending entry would never converge and would expire
        // as a false alarm. Any older adoption for the id is stale by the same token.
        const auto inFile = m_keys.find(*agentId);
        auto fileState =
            inFile != m_keys.end() ? std::optional<std::vector<std::uint8_t>> {inFile->second.key} : std::nullopt;
        if (fileState && *fileState == decoded)
        {
            expired = expireAdoptedLocked(now);
            m_pending.erase(*agentId);
            lock.unlock();
            reportExpired(expired);
            LOGFN_DEBUG1(
                logFn(), "client.keys already carries the key issued to agent %u; nothing to adopt.", *agentId);
            return true;
        }
        // A newer adoption for the same id (two re-enrollments before the file caught up): the key
        // it replaces is one authd may still write first, so it joins the superseded keys. Inherited
        // BEFORE the sweep below: a previous adoption past its grace is still a key this node issued
        // and the file may still land it (the typical chain is an expiry, an unknown_agent answer and
        // a re-enrollment here, with the sync then delivering the older key first).
        PendingEntry adoption {
            AgentEntry {std::move(decoded), std::move(*addressRule)}, now, {}, fileState.has_value()};
        if (auto previous = m_pending.find(*agentId); previous != m_pending.end())
        {
            adoption.supersededKeys = std::move(previous->second.supersededKeys);
            // The same key adopted again supersedes nothing, and a key already listed is not
            // listed twice: both would only eat into kMaxSupersededKeys.
            auto& previousKey = previous->second.entry.key;
            if (previousKey != adoption.entry.key && // decoded was moved into the adoption above

                std::find(adoption.supersededKeys.begin(), adoption.supersededKeys.end(), previousKey) ==
                    adoption.supersededKeys.end())
            {
                adoption.supersededKeys.push_back(std::move(previousKey));
            }
            adoption.idSeenInFile = adoption.idSeenInFile || previous->second.idSeenInFile;
            adoption.saturated = previous->second.saturated;
        }
        expired = expireAdoptedLocked(now);
        if (fileState && std::find(adoption.supersededKeys.begin(), adoption.supersededKeys.end(), *fileState) ==
                             adoption.supersededKeys.end())
        {
            adoption.supersededKeys.push_back(std::move(*fileState));
        }
        if (adoption.supersededKeys.size() > kMaxSupersededKeys)
        {
            adoption.supersededKeys.erase(adoption.supersededKeys.begin(),
                                          adoption.supersededKeys.end() -
                                              static_cast<std::ptrdiff_t>(kMaxSupersededKeys));
            adoption.saturated = true;
        }
        // Beside the file's table, never in it: agentsLoaded()/entriesSkipped() keep describing
        // the file, and the next reload() decides when the file has moved on (see the header).
        m_pending.insert_or_assign(*agentId, std::move(adoption));
        lock.unlock();
        reportExpired(expired);
        LOGFN_DEBUG1(logFn(),
                     "Adopted the key issued to agent %u; in service until client.keys carries it (%lld s at most).",
                     *agentId,
                     static_cast<long long>(kAdoptionGrace.count()));
        return true;
    }

    std::vector<Keystore::ExpiredAdoption> Keystore::expireAdoptedLocked(std::chrono::steady_clock::time_point now)
    {
        std::vector<ExpiredAdoption> expired;
        for (auto it = m_pending.begin(); it != m_pending.end();)
        {
            if (now - it->second.adoptedAt > kAdoptionGrace)
            {
                expired.push_back(ExpiredAdoption {it->first, it->second.idSeenInFile});
                m_adoptionExpiriesTotal.fetch_add(1, std::memory_order_relaxed);
                it = m_pending.erase(it);
            }
            else
            {
                ++it;
            }
        }
        return expired;
    }

    void Keystore::reportExpired(const std::vector<ExpiredAdoption>& expired)
    {
        for (const auto& entry : expired)
        {
            // What the file did show in the meantime tells the causes apart: an id it never carried
            // is an enrollment the writer or the sync has not landed (or an agent removed before
            // they did -- the keystore gets no removal signal, only the file); an id still on an
            // older key is a rotation they have not landed.
            const char* fileShowed =
                entry.idSeenInFile ? "the file still shows an older key for it"
                                   : "the file never showed the agent (not written yet, or removed before it was)";
            LOGFN_DEBUG1(logFn(),
                         "Dropped the key adopted for agent %u: not seen in '%s' within %lld s; %s.",
                         entry.id,
                         m_path.c_str(),
                         static_cast<long long>(kAdoptionGrace.count()),
                         fileShowed);
            // Throttled: a writer or sync that stalls during an enrollment wave expires every
            // adoption in one sweep, and one line per entry would flood the log.
            if (const auto d = m_expiryThrottle.record())
            {
                LOGFN_WARN(logFn(),
                           "Dropped the key adopted for agent %u from its enrollment: not seen in '%s' within %lld s "
                           "(%s). %llu adopted key(s) expired %s; check that wazuh-authd is writing the file (or, on "
                           "a worker, that the cluster synchronization is running).",
                           entry.id,
                           m_path.c_str(),
                           static_cast<long long>(kAdoptionGrace.count()),
                           fileShowed,
                           static_cast<unsigned long long>(d.total),
                           d.period().c_str());
            }
        }
    }

    std::size_t Keystore::adoptionsPending() const
    {
        const auto now = m_clock();
        std::lock_guard<std::mutex> lock(m_mutex);
        // A plain count, never a sweep: this is read by metrics scrapes and status probes, which
        // must not move counters or write log lines (and how often they run must not decide when
        // an expiry is counted). reload(), upsert() and the watcher's cycle do the sweeping.
        return static_cast<std::size_t>(std::count_if(m_pending.begin(),
                                                      m_pending.end(),
                                                      [now](const auto& pending)
                                                      { return now - pending.second.adoptedAt <= kAdoptionGrace; }));
    }

    std::optional<AgentLookup> Keystore::lookup(AgentId agentId, std::string_view peerIp) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        // An adopted entry wins while it is in service: after a rotation the file still carries the
        // previous key until authd's writer pass lands. Expired ones are ignored here (lookup() is
        // const and hot) and swept by reload(), upsert() and the watcher. The clock is consulted
        // only when the id has an adopted entry: m_pending is empty almost always, and this is
        // the path every authenticated request takes.
        if (!m_pending.empty())
        {
            if (const auto pending = m_pending.find(agentId);
                pending != m_pending.end() && m_clock() - pending->second.adoptedAt <= kAdoptionGrace)
            {
                return AgentLookup {pending->second.entry.key, pending->second.entry.address.matches(peerIp)};
            }
        }
        const auto it = m_keys.find(agentId);
        if (it == m_keys.end())
        {
            return std::nullopt;
        }
        // Key copied and rule evaluated under the same lock, so the two answers always describe the
        // same entry and no reference into the table escapes.
        return AgentLookup {it->second.key, it->second.address.matches(peerIp)};
    }

} // namespace remoted::auth
