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

#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include "common/logThrottle.hpp" // Safe in a header: LogThrottle deliberately does not log.
#include "jwt/secureBytes.hpp"

namespace remoted::auth
{

    /**
     * @brief Read-only, in-memory replica of authd's enrollment token store
     *        (etc/enrollment_tokens.json), keyed by token id, with the `wazuh-enroll+jwt` HS256 key of
     *        every credential-bearing token already derived. Backs the enrollment-token path of
     *        EnrollmentAuthenticator (issue #38993): a bearer whose `kid` names a token id is verified
     *        against the key cached here, and its status (expired / revoked) is answered from here too.
     *
     * Same operational shape as PasswordKeySource, and deliberately the same discipline: authd's
     * master is the ONLY writer of the store (enrollment_token_store.c writes it atomically --
     * temp file + rename), the cluster's own file sync replicates it to every worker
     * (framework/wazuh/core/cluster/cluster.json lists it alongside client.keys and authd.pass), and
     * this class never creates, writes or repairs the file. The watcher (inotify + a periodic
     * fallback poll + content-hash change detection, so a rewrite caught mid-read is never adopted
     * torn) mirrors PasswordKeySource/Keystore exactly.
     *
     * What is replicated, per token: the id (the `kid` the agent presents), the HS256 key derived
     * ONCE per load from the 16-byte secret through the shared jwt/enrollKeyDerivation.hpp
     * (`WAZUH-ENROLL-TOKEN-KEY`; authd replicates the same construction in C), `expires` and
     * `revoked`. Tokens minted WITHOUT a credential (`secret: null` -- the operator chose a public
     * token that only pins the manager's CA) carry nothing an agent could authenticate with, so
     * they are not replicated at all: a `kid` naming one is simply unknown here. Uses/max_uses stay
     * authd's business: remoted forwards `token_id` and authd consumes the use (9024 when exhausted).
     *
     * Failure modes, all fail-closed: an absent file is an EMPTY replica (not an error: no token has
     * been minted yet, or a worker has not received the sync); a malformed file keeps the PREVIOUS
     * replica and counts a reload failure (a store authd wrote is always well-formed, so this is
     * corruption or an outside edit, and dropping every token because of it would let a bad edit
     * revoke a fleet's enrollment); a torn read is retried a few times like PasswordKeySource does.
     *
     * reloadIfMissing() is the cluster-sync mitigation of the design (P35b): a token minted on the
     * master a moment ago may not have reached this worker's file yet when the agent enrolls
     * through it, so an unknown `kid` forces one re-read before the request is rejected --
     * rate-limited (kMissingKidReloadMinIntervalMs) so a peer probing random ids cannot turn the
     * store into a per-request file read.
     */
    class TokenKeySource
    {
    public:
        /// Path to authd's enrollment token store, relative to the manager's home directory
        /// (ENROLLMENT_TOKENS_FILE in os_auth's defs.h).
        static constexpr const char* kDefaultPath = "etc/enrollment_tokens.json";

        /// Built-in refresh interval when the caller passes <=0 (matches PasswordKeySource's).
        static constexpr int kDefaultRefreshIntervalSeconds = 10;

        /// Minimum spacing between two forced re-reads triggered by unknown `kid`s (reloadIfMissing()).
        static constexpr int kMissingKidReloadMinIntervalMs = 1000;

        /// Largest store this class will parse. authd's store holds at most a few hundred tokens of
        /// ~300 bytes each; a file past this size is not a store this daemon should be reading.
        static constexpr std::size_t kMaxStoreBytes = 8U * 1024U * 1024U;

        /// What the replica knows about one credential-bearing token.
        struct TokenEntry
        {
            jwt_profile::v1::SecureBytes key; ///< HKDF-derived 32-byte HS256 key (a wiped-on-destroy copy).
            std::int64_t expires {0};         ///< Absolute Unix time; the token is usable while now < expires.
            bool revoked {false};
        };

        /// @brief Store health behind the remoted.enroll.token_store.* pull metrics and GET /status.
        struct Diagnostics
        {
            std::size_t tokens {0};           ///< Credential-bearing tokens in the replica right now.
            std::uint64_t reloads {0};        ///< Successful loads (the initial one included).
            std::uint64_t reloadFailures {0}; ///< Loads that kept the previous replica (malformed/torn).
            bool lastLoadOk {false};          ///< Whether the most recent load attempt succeeded.
        };

        /**
         * @param path Path to the token store. An initial reload() runs synchronously in the
         *             constructor; a missing file is not an error -- the replica simply starts empty.
         * @param refreshIntervalSeconds Fallback poll interval of the background watcher (seconds).
         *             <=0 -> kDefaultRefreshIntervalSeconds. The facade passes the same
         *             `remoted.enroll_password_refresh_interval` PasswordKeySource reads.
         * @param isWorkerNode Whether this manager is a cluster worker -- an absent file is then the
         *             expected wait for the master's sync (DEBUG1), never a warning.
         */
        explicit TokenKeySource(std::string path = kDefaultPath,
                                int refreshIntervalSeconds = kDefaultRefreshIntervalSeconds,
                                bool isWorkerNode = false);

        ~TokenKeySource();

        TokenKeySource(const TokenKeySource&) = delete;
        TokenKeySource& operator=(const TokenKeySource&) = delete;

        /**
         * @brief Re-read the store and rebuild the replica.
         *
         * Always re-reads when called; the watcher decides separately whether calling this is
         * warranted. Guarded against a concurrent rewrite the way PasswordKeySource::reload() is:
         * the content hash is captured before and after reading and the read is retried if they
         * differ.
         *
         * @return true when the replica now reflects the file (an absent file counts: the replica
         *         is then empty), false when the previous replica was kept (malformed content, an
         *         unstable read across every retry, or HKDF unavailable).
         */
        bool reload();

        /// @return A copy of the entry for @p kid, or nullopt when no credential-bearing token has
        ///         that id in the current replica. Never re-reads the file.
        std::optional<TokenEntry> lookup(std::string_view kid) const;

        /**
         * @brief The P35b mitigation: force one re-read because @p kid was not found.
         *
         * @return true when a re-read was actually performed (the caller should lookup() again);
         *         false when the rate limit suppressed it -- another unknown `kid` forced a re-read
         *         less than kMissingKidReloadMinIntervalMs ago, so the replica is already as fresh
         *         as the file, and the caller's rejection stands.
         */
        bool reloadIfMissing(std::string_view kid);

        /// Snapshot for the metrics dump and GET /status. Takes the replica lock briefly.
        Diagnostics diagnostics() const;

    private:
        using Replica = std::unordered_map<std::string, TokenEntry>;

        void watcherLoop();
        void watcherLoopBody();
        void closeWatchFds() noexcept;
        void drainInotifyEvents();
        bool fileLooksChanged();
        /// Installs @p replica; records in m_lastReloadChangedSet whether the set of recognised tokens
        /// (ids, expiry, revocation) differs from the previous one -- authd rewrites the store on
        /// EVERY consumed use (the `uses` counter lives in the same file), so most reloads change
        /// nothing this class cares about, and the watcher logs those at DEBUG1 rather than INFO.
        void adoptReplica(Replica replica);

        std::string m_path;
        mutable std::mutex m_mutex;
        Replica m_replica;
        bool m_lastLoadOk {false};
        bool m_lastReloadChangedSet {false};
        std::uint64_t m_reloads {0};
        std::uint64_t m_reloadFailures {0};

        int m_refreshIntervalSeconds;
        int m_inotifyFd {-1};
        int m_watchDescriptor {-1};
        int m_stopEventFd {-1};
        std::thread m_watcherThread;

        /// Fallback stop signal, checked every loop iteration independent of m_stopEventFd (see
        /// PasswordKeySource for the eventfd-failure rationale).
        std::atomic<bool> m_stopping {false};

        std::mutex m_reloadMutex;
        bool m_hasBaseline {false};
        std::vector<std::uint8_t> m_lastHash;

        /// steady_clock nanoseconds of the last forced re-read (reloadIfMissing()); 0 = never.
        std::atomic<std::int64_t> m_lastForcedReloadNs {0};

        bool m_isWorkerNode;

        /// Throttles the "store is malformed / unreadable" warning: the watcher retries every
        /// m_refreshIntervalSeconds, so a bad file would otherwise flood wazuh-manager.log.
        remoted::common::LogThrottle m_invalidThrottle;

        /// The same, for a file that DID load with some of its records dropped: counted apart so the
        /// two warnings never report each other's totals.
        remoted::common::LogThrottle m_droppedThrottle;
    };

} // namespace remoted::auth
