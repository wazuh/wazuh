/*
 * Wazuh auth middleware (framework-agnostic)
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "tokenKeySource.hpp"

#include <cerrno>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iterator>
#include <optional>
#include <sstream>
#include <utility>

#include <openssl/crypto.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "hashHelper.h"
#include "json.hpp"
#include "jwt/base64Url.hpp"
#include "jwt/enrollKeyDerivation.hpp"
#include "jwt/jwtEnrollProfileV1.hpp"
#include "loggerHelper.h"

namespace remoted::auth
{

    namespace
    {
        // Same rationale as passwordKeySource.cpp: loggerHelper.h stays out of the header.
        constexpr auto TOKEN_KEY_SOURCE_LOGTAG {"wazuh-manager-remoted:tokenKeySource"};

        const LogFn& logFn()
        {
            static const LogFn instance {TOKEN_KEY_SOURCE_LOGTAG};
            return instance;
        }

        constexpr int kMaxReadAttempts {3};
        constexpr auto kRetryBackoff {std::chrono::milliseconds(20)};

        constexpr std::uint32_t kWatchMask {IN_MODIFY | IN_CLOSE_WRITE | IN_MOVE_SELF | IN_DELETE_SELF};

        /// The store's `version` field (ETOKEN_STORE_VERSION in os_auth/src/enrollment_token_store.c).
        constexpr int kStoreVersion {1};

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

        /// Whole-file read, bounded by kMaxStoreBytes. nullopt when the file cannot be opened or is
        /// over the cap (the caller distinguishes "absent" beforehand through the hash).
        std::optional<std::string> readWholeFile(const std::string& path)
        {
            std::ifstream in(path, std::ios::binary);
            if (!in)
            {
                return std::nullopt;
            }
            std::string text;
            text.reserve(4096);
            char buffer[4096];
            while (in.read(buffer, sizeof(buffer)) || in.gcount() > 0)
            {
                text.append(buffer, static_cast<std::size_t>(in.gcount()));
                if (text.size() > TokenKeySource::kMaxStoreBytes)
                {
                    return std::nullopt;
                }
            }
            return text;
        }

        /// A JSON number that is a non-negative integer fitting an int64 (the store writes epoch
        /// seconds through cJSON's doubles, so an integral double is what actually arrives).
        std::optional<std::int64_t> asUnixTime(const nlohmann::json& value)
        {
            if (!value.is_number())
            {
                return std::nullopt;
            }
            const double d = value.get<double>();
            if (!(d >= 0.0) || d > 9.2e18 || std::floor(d) != d)
            {
                return std::nullopt;
            }
            return static_cast<std::int64_t>(d);
        }

        struct ParsedEntry
        {
            std::string id;
            TokenKeySource::TokenEntry entry;
        };

        /**
         * @brief One store entry -> its replica entry. nullopt with @p reason set when the entry is
         *        malformed; nullopt with @p reason EMPTY when the entry is well-formed but carries no
         *        credential (`secret: null`) and is therefore not replicated.
         *
         * Only the fields remoted needs are validated (id, secret, expires, revoked); the rest of
         * authd's record (adr, pin/ca, created, uses, max_uses, description) is authd's business and
         * is deliberately not looked at, so a future field on authd's side never breaks this reader.
         */
        std::optional<ParsedEntry> parseEntry(const nlohmann::json& item, std::string& reason)
        {
            using jwt_profile::v1::base64UrlDecodeCanonical;
            using jwt_profile::v1::isCanonicalBase64UrlOf;
            using jwt_profile::v1::enroll::kTokenIdBytes;
            using jwt_profile::v1::enroll::kTokenSecretBytes;

            if (!item.is_object())
            {
                reason = "an entry is not an object";
                return std::nullopt;
            }

            const auto idIt = item.find("id");
            if (idIt == item.end() || !idIt->is_string() ||
                !isCanonicalBase64UrlOf(idIt->get_ref<const std::string&>(), kTokenIdBytes))
            {
                reason = "an entry has an invalid id";
                return std::nullopt;
            }

            const auto secretIt = item.find("secret");
            if (secretIt == item.end() || secretIt->is_null())
            {
                // Well-formed, credential-less: nothing an agent could present, nothing to replicate.
                reason.clear();
                return std::nullopt;
            }
            if (!secretIt->is_string() ||
                !isCanonicalBase64UrlOf(secretIt->get_ref<const std::string&>(), kTokenSecretBytes))
            {
                reason = "an entry has an invalid secret";
                return std::nullopt;
            }

            const auto expiresIt = item.find("expires");
            const auto expires = expiresIt == item.end() ? std::nullopt : asUnixTime(*expiresIt);
            if (!expires)
            {
                reason = "an entry has an invalid expires";
                return std::nullopt;
            }

            const auto revokedIt = item.find("revoked");
            if (revokedIt == item.end() || !revokedIt->is_boolean())
            {
                reason = "an entry has an invalid revoked flag";
                return std::nullopt;
            }

            auto secretBytes = base64UrlDecodeCanonical(secretIt->get_ref<const std::string&>());
            if (!secretBytes || secretBytes->size() != kTokenSecretBytes)
            {
                reason = "an entry has an invalid secret";
                return std::nullopt;
            }
            // Bound by reference (operator*), not through operator->: the static analyzer models the latter
            // as a temporary and reports its inner pointer as used after deallocation.
            std::string& rawSecret = *secretBytes;
            jwt_profile::v1::SecureBytes secret {reinterpret_cast<const std::uint8_t*>(rawSecret.data()),
                                                 rawSecret.size()};
            // The decoded text is a plain std::string: wipe it before it goes out of scope.
            OPENSSL_cleanse(rawSecret.data(), rawSecret.size());

            // The one HKDF construction authd replicates in C (src/shared/src/enrollment_token.c);
            // pinned by test_vectors::enroll_token on both sides.
            auto key = jwt_profile::v1::enroll::deriveEnrollTokenKey(secret);
            if (!key)
            {
                reason = "HKDF unavailable";
                return std::nullopt;
            }

            ParsedEntry parsed;
            parsed.id = idIt->get<std::string>();
            parsed.entry.key = std::move(*key);
            parsed.entry.expires = *expires;
            parsed.entry.revoked = revokedIt->get<bool>();
            return parsed;
        }

        /// The whole store -> a replica. nullopt with @p reason when the DOCUMENT is not a store.
        ///
        /// One ENTRY that cannot be read is a different thing from a document that cannot: it is dropped,
        /// counted in @p skipped, and the rest of the file still becomes the replica -- the same answer
        /// authd's own loader gives. Refusing the file over one record was how a single token with, say, a
        /// negative `expires` (a record a manager could write before the lifetime was bounded) froze every
        /// worker's replica at whatever it held before, permanently, and took token enrollment down with
        /// it (issue #39133). @p reason then names the last record dropped, for the log.
        ///
        /// A duplicate id stays a document-level refusal: authd never writes two records with one id, so
        /// it means the file was edited by hand, and choosing between them would be guessing.
        std::optional<std::unordered_map<std::string, TokenKeySource::TokenEntry>>
        parseStore(const std::string& text, std::string& reason, std::size_t& skipped)
        {
            const auto root = nlohmann::json::parse(text, nullptr, false);
            if (root.is_discarded() || !root.is_object())
            {
                reason = "not a JSON object";
                return std::nullopt;
            }
            const auto versionIt = root.find("version");
            if (versionIt == root.end() || !versionIt->is_number() || versionIt->get<double>() != kStoreVersion)
            {
                reason = "unsupported or missing version";
                return std::nullopt;
            }
            const auto tokensIt = root.find("tokens");
            if (tokensIt == root.end() || !tokensIt->is_array())
            {
                reason = "missing tokens array";
                return std::nullopt;
            }

            std::unordered_map<std::string, TokenKeySource::TokenEntry> replica;
            for (const auto& item : *tokensIt)
            {
                std::string entryReason;
                auto parsed = parseEntry(item, entryReason);
                if (!parsed)
                {
                    if (entryReason.empty())
                    {
                        continue; // credential-less token: skipped by design
                    }
                    reason = std::move(entryReason);
                    ++skipped;
                    continue;
                }
                if (!replica.emplace(std::move(parsed->id), std::move(parsed->entry)).second)
                {
                    // authd never writes two records with one id; two here means the file was
                    // edited by hand, and picking either silently would be guessing.
                    reason = "duplicate token id";
                    return std::nullopt;
                }
            }
            return replica;
        }

        std::int64_t steadyNowNs()
        {
            return std::chrono::duration_cast<std::chrono::nanoseconds>(
                       std::chrono::steady_clock::now().time_since_epoch())
                .count();
        }
    } // namespace

    TokenKeySource::TokenKeySource(std::string path, int refreshIntervalSeconds, bool isWorkerNode)
        : m_path(std::move(path))
        , m_refreshIntervalSeconds(refreshIntervalSeconds > 0 ? refreshIntervalSeconds : kDefaultRefreshIntervalSeconds)
        , m_isWorkerNode(isWorkerNode)
    {
        const bool loaded = reload();
        const auto diag = diagnostics();
        if (loaded && diag.tokens > 0)
        {
            LOGFN_INFO(logFn(),
                       "Enrollment token store loaded from '%s' (%zu token(s) with a credential).",
                       m_path.c_str(),
                       diag.tokens);
        }
        else if (loaded)
        {
            // Absent or empty: the ordinary state of a manager that has minted no token yet (or of a
            // worker still waiting for the master's sync) -- informational, never a warning.
            LOGFN_DEBUG1(logFn(),
                         "No enrollment token with a credential in '%s' yet%s; token-based enrollment requests "
                         "will be rejected until one is minted%s.",
                         m_path.c_str(),
                         m_isWorkerNode ? " (not synchronized from the master node)" : "",
                         m_isWorkerNode ? " on the master and synchronized" : "");
        }
        // A malformed store already warned from reload().

        m_inotifyFd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (m_inotifyFd < 0)
        {
            LOGFN_WARN(logFn(),
                       "inotify_init1 failed (errno=%d); enrollment token store hot-reload falls back to the %d s "
                       "poll only.",
                       errno,
                       m_refreshIntervalSeconds);
        }
        else
        {
            m_watchDescriptor = inotify_add_watch(m_inotifyFd, m_path.c_str(), kWatchMask);
            if (m_watchDescriptor < 0)
            {
                const int watchErrno = errno;
                if (watchErrno == ENOENT)
                {
                    // No store yet: expected (see above). The poll notices the file appearing and
                    // drainInotifyEvents()/the poll re-arm the watch from then on.
                    LOGFN_DEBUG1(logFn(),
                                 "Cannot watch '%s' for changes yet (no enrollment token store); hot-reload falls "
                                 "back to the %d s poll only until it appears.",
                                 m_path.c_str(),
                                 m_refreshIntervalSeconds);
                }
                else
                {
                    LOGFN_WARN(
                        logFn(),
                        "Could not watch '%s' for changes (errno=%d); hot-reload falls back to the %d s poll only.",
                        m_path.c_str(),
                        watchErrno,
                        m_refreshIntervalSeconds);
                }
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
            m_watcherThread = std::thread(&TokenKeySource::watcherLoop, this);
        }
        catch (...)
        {
            closeWatchFds();
            throw;
        }
    }

    void TokenKeySource::closeWatchFds() noexcept
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

    TokenKeySource::~TokenKeySource()
    {
        try
        {
            m_stopping.store(true);

            if (m_stopEventFd >= 0)
            {
                const std::uint64_t one {1};
                if (write(m_stopEventFd, &one, sizeof(one)) < 0)
                {
                    LOGFN_DEBUG1(
                        logFn(), "Could not signal the enrollment token store watcher to stop (errno=%d).", errno);
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

    void TokenKeySource::watcherLoop()
    {
        try
        {
            watcherLoopBody();
        }
        catch (const std::exception& e)
        {
            LOGFN_ERROR(logFn(),
                        "The enrollment token store watcher thread stopped on an unexpected exception: %s. Tokens "
                        "minted from now on will not be recognized until wazuh-remoted is restarted.",
                        e.what());
        }
        catch (...)
        {
            LOGFN_ERROR(logFn(),
                        "The enrollment token store watcher thread stopped on a non-standard exception. Tokens "
                        "minted from now on will not be recognized until wazuh-remoted is restarted.");
        }
    }

    void TokenKeySource::watcherLoopBody()
    {
        LOGFN_DEBUG1(logFn(),
                     "Enrollment token store watcher thread started (refresh interval %d s).",
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

            const int timeoutMs = m_refreshIntervalSeconds * 1000;
            const int ready = poll(fds, static_cast<nfds_t>(nfds), timeoutMs);

            if (ready < 0)
            {
                if (errno == EINTR)
                {
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
                LOGFN_WARN(logFn(), "poll() on the enrollment token store watcher failed (errno=%d).", errno);
                std::this_thread::sleep_for(std::chrono::seconds(m_refreshIntervalSeconds));
                continue;
            }

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

            // The watch is added at construction only if the file existed then; a store that
            // appears later (first mint, first cluster sync) is noticed by the poll and armed here.
            if (m_inotifyFd >= 0 && m_watchDescriptor < 0)
            {
                m_watchDescriptor = inotify_add_watch(m_inotifyFd, m_path.c_str(), kWatchMask);
                if (m_watchDescriptor >= 0)
                {
                    LOGFN_DEBUG1(logFn(), "Enrollment token store watch armed on '%s'.", m_path.c_str());
                }
            }

            if (fileLooksChanged())
            {
                if (reload())
                {
                    bool changedSet = false;
                    std::size_t tokens = 0;
                    {
                        std::lock_guard<std::mutex> lock(m_mutex);
                        changedSet = m_lastReloadChangedSet;
                        tokens = m_replica.size();
                    }
                    // authd rewrites the store on every consumed use (`uses` lives in the same
                    // file), so a reload that changed nothing this replica recognises -- the common
                    // case under a fleet enrolling -- must not put one INFO line per enrollment in
                    // wazuh-manager.log. A mint, a revocation or an expiry change is worth one.
                    if (changedSet)
                    {
                        LOGFN_INFO(logFn(),
                                   "Enrollment token store reloaded from '%s' (%zu token(s) with a credential).",
                                   m_path.c_str(),
                                   tokens);
                    }
                    else
                    {
                        LOGFN_DEBUG1(logFn(),
                                     "Enrollment token store re-read from '%s' (%zu token(s), no change to the "
                                     "recognised set).",
                                     m_path.c_str(),
                                     tokens);
                    }
                }
                // A failed reload already warned (throttled) from reload().
            }
        }

        LOGFN_DEBUG1(logFn(), "Enrollment token store watcher thread stopped.");
    }

    void TokenKeySource::drainInotifyEvents()
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

        // authd replaces the store atomically (temp file + rename), so every write invalidates the
        // watch on the old inode: re-arm on the new one. ENOENT (deleted, not replaced) is left to
        // the poll loop, which re-arms once the file is back.
        if (m_watchDescriptor >= 0)
        {
            inotify_rm_watch(m_inotifyFd, m_watchDescriptor);
        }
        m_watchDescriptor = inotify_add_watch(m_inotifyFd, m_path.c_str(), kWatchMask);
        if (m_watchDescriptor < 0 && errno != ENOENT)
        {
            LOGFN_WARN(logFn(),
                       "Could not re-arm the enrollment token store watch after it was invalidated (errno=%d); "
                       "falling back to the %d s poll only.",
                       errno,
                       m_refreshIntervalSeconds);
        }
        else if (m_watchDescriptor >= 0)
        {
            LOGFN_DEBUG1(logFn(), "Enrollment token store watch re-armed after the file was replaced.");
        }
    }

    bool TokenKeySource::fileLooksChanged()
    {
        std::lock_guard<std::mutex> lock(m_reloadMutex);

        const auto currentHash = hashFileOrNullopt(m_path);
        if (!currentHash)
        {
            // Absent: only a change if the replica still holds tokens (or a baseline) -- otherwise
            // every poll tick would re-run reload() on a file that is simply not there yet.
            return m_hasBaseline;
        }
        return !m_hasBaseline || *currentHash != m_lastHash;
    }

    void TokenKeySource::adoptReplica(Replica replica)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        bool changed = replica.size() != m_replica.size();
        for (auto it = replica.begin(); !changed && it != replica.end(); ++it)
        {
            const auto old = m_replica.find(it->first);
            changed = old == m_replica.end() || old->second.expires != it->second.expires ||
                      old->second.revoked != it->second.revoked || !(old->second.key == it->second.key);
        }
        m_lastReloadChangedSet = changed;
        m_replica = std::move(replica);
        m_lastLoadOk = true;
        ++m_reloads;
    }

    bool TokenKeySource::reload()
    {
        std::lock_guard<std::mutex> reloadLock(m_reloadMutex);

        for (int attempt = 0; attempt < kMaxReadAttempts; ++attempt)
        {
            const auto preHash = hashFileOrNullopt(m_path);
            if (!preHash)
            {
                // No store: an empty replica, and a valid state. m_hasBaseline is cleared so a file
                // that later appears -- even byte-identical to one seen before -- is reloaded.
                adoptReplica(Replica {});
                m_hasBaseline = false;
                m_lastHash.clear();
                return true;
            }

            auto text = readWholeFile(m_path);

            const auto postHash = hashFileOrNullopt(m_path);
            if (postHash && *postHash == *preHash)
            {
                std::string reason;
                std::size_t skipped = 0;
                auto replica = text ? parseStore(*text, reason, skipped) : std::nullopt;
                if (text)
                {
                    std::string& rawText = *text;                    // by reference, see parseStore()'s secret wipe
                    OPENSSL_cleanse(rawText.data(), rawText.size()); // it carries every token's secret
                }
                else
                {
                    reason = "unreadable or over the size cap";
                }

                m_hasBaseline = true;
                m_lastHash = *preHash;

                if (!replica)
                {
                    std::size_t kept = 0;
                    {
                        std::lock_guard<std::mutex> lock(m_mutex);
                        m_lastLoadOk = false;
                        ++m_reloadFailures;
                        kept = m_replica.size();
                    }
                    if (const auto d = m_invalidThrottle.record())
                    {
                        LOGFN_WARN(logFn(),
                                   "'%s' is not a valid enrollment token store (%s); keeping the previous %zu "
                                   "token(s). %llu failed load(s) in the last %d s. The file is written by "
                                   "wazuh-manager-authd on the master node and must not be edited by hand.",
                                   m_path.c_str(),
                                   reason.c_str(),
                                   kept,
                                   static_cast<unsigned long long>(d.total),
                                   remoted::common::LogThrottle::kDefaultWindowSeconds);
                    }
                    return false;
                }

                if (skipped > 0)
                {
                    // The load SUCCEEDED: the replica below is the file minus the records that could not
                    // be read, which is what keeps one bad token from costing a worker every other one.
                    // Still said out loud, throttled, because the file is written by one process and a
                    // record it cannot read back is a defect somewhere upstream.
                    if (const auto d = m_droppedThrottle.record())
                    {
                        LOGFN_WARN(logFn(),
                                   "%zu record(s) of the enrollment token store '%s' could not be read (%s) "
                                   "and were dropped; the other %zu token(s) are replicated. %llu such load(s) "
                                   "in the last %d s. The file is written by wazuh-manager-authd on the master "
                                   "node and must not be edited by hand.",
                                   skipped,
                                   m_path.c_str(),
                                   reason.c_str(),
                                   replica->size(),
                                   static_cast<unsigned long long>(d.total),
                                   remoted::common::LogThrottle::kDefaultWindowSeconds);
                    }
                }

                adoptReplica(std::move(*replica));
                return true;
            }

            LOGFN_DEBUG1(logFn(),
                         "The enrollment token store changed while reloading (attempt %d/%d), retrying.",
                         attempt + 1,
                         kMaxReadAttempts);
            if (attempt + 1 < kMaxReadAttempts)
            {
                std::this_thread::sleep_for(kRetryBackoff);
            }
        }

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_lastLoadOk = false;
            ++m_reloadFailures;
        }
        LOGFN_WARN(logFn(),
                   "The enrollment token store kept changing across %d attempts; keeping the previous replica.",
                   kMaxReadAttempts);
        return false;
    }

    std::optional<TokenKeySource::TokenEntry> TokenKeySource::lookup(std::string_view kid) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it = m_replica.find(std::string(kid));
        if (it == m_replica.end())
        {
            return std::nullopt;
        }
        TokenEntry copy;
        copy.key = jwt_profile::v1::SecureBytes(it->second.key.data(), it->second.key.size()); // wiped on destroy
        copy.expires = it->second.expires;
        copy.revoked = it->second.revoked;
        return copy;
    }

    bool TokenKeySource::reloadIfMissing(std::string_view /*kid*/)
    {
        // One re-read per kMissingKidReloadMinIntervalMs at most, process-wide: a CAS on the last
        // forced-reload timestamp means concurrent unknown-kid requests elect exactly one reader.
        const auto now = steadyNowNs();
        auto last = m_lastForcedReloadNs.load();
        constexpr std::int64_t kMinIntervalNs = static_cast<std::int64_t>(kMissingKidReloadMinIntervalMs) * 1000000;
        if (last != 0 && now - last < kMinIntervalNs)
        {
            return false;
        }
        if (!m_lastForcedReloadNs.compare_exchange_strong(last, now))
        {
            return false;
        }
        LOGFN_DEBUG2(logFn(), "Unknown enrollment token id; re-reading '%s' once before rejecting.", m_path.c_str());
        reload();
        return true;
    }

    TokenKeySource::Diagnostics TokenKeySource::diagnostics() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        Diagnostics diag;
        diag.tokens = m_replica.size();
        diag.reloads = m_reloads;
        diag.reloadFailures = m_reloadFailures;
        diag.lastLoadOk = m_lastLoadOk;
        return diag;
    }

} // namespace remoted::auth
