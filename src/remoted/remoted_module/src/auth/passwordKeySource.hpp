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

#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "common/logThrottle.hpp" // Safe in a header: LogThrottle deliberately does not log.
#include "jwt/secureBytes.hpp"

namespace remoted::auth
{

    /**
     * @brief Turns authd's enrollment password (etc/authd.pass) into the `wazuh-enroll+jwt` HS256 key,
     *        hot-reloaded on change. Backs Password-mode enrollment auth (see EnrollmentAuthenticator).
     *
     * Strictly read-only, on every node -- master or worker alike. authd itself is asymmetric:
     * only the master ever generates the password file (w_authd_load_password); a worker only
     * reads it, and a background watcher (run_authpass_watcher, os_auth/src/main-server.c) picks
     * it up once the cluster's own file sync delivers it (framework/wazuh/core/cluster/cluster.json
     * already lists authd.pass alongside client.keys). This class must never create or write the
     * file -- generation stays authd's exclusive job.
     *
     * Parsing byte-matches authd's own read_password_line() (os_auth/src/auth.c): first line
     * only, up to 4096 bytes, trailing '\r'/'\n' stripped, rejected if the remaining length is
     * <= 2 or entirely whitespace. This must stay exact: the manager's two enrollment paths
     * (this one and legacy port 1515) have to agree on which passwords are valid, or an operator
     * could set a password that authd accepts but remoted silently treats as absent (or vice
     * versa) -- either way, a fail-closed contract that's supposed to be consistent stops being
     * one.
     *
     * The signing key is not the password itself: currentKey() returns the 32-byte HS256 key
     * derived via HKDF-SHA256 (salt 32 x 0x00, info = "WAZUH-ENROLL-JWT-KEY" + 0x01) by the
     * shared jwt/enrollKeyDerivation.hpp -- the agent derives the same key. Derivation runs once
     * per file change and is cached -- never per request. See the Agent enrollment chapter of
     * remoted_module/README.md for a verified worked example (known-answer vector).
     *
     * Hot-reload mirrors Keystore exactly (inotify + a periodic fallback poll + content-hash
     * change detection, so a rewrite caught mid-read can never be adopted torn) -- the two files
     * have the same operational shape: an operator/cluster-sync-managed secret a running process
     * must notice without a restart.
     */
    class PasswordKeySource
    {
    public:
        /// Path to authd's enrollment password file, relative to the manager's home directory.
        static constexpr const char* kDefaultPath = "etc/authd.pass";

        /// Built-in refresh interval when the caller passes <=0 (matches Keystore's own default).
        static constexpr int kDefaultRefreshIntervalSeconds = 10;

        /**
         * @param path Path to authd's password file. An initial reload() runs synchronously in
         *             the constructor; a missing or invalid file is not an error -- currentKey()
         *             simply starts at nullopt (fail closed for Password mode).
         * @param refreshIntervalSeconds How often the background watcher re-checks the file as a
         *             fallback to the inotify subscription (seconds). <=0 -> kDefaultRefreshIntervalSeconds.
         */
        explicit PasswordKeySource(std::string path = kDefaultPath,
                                   int refreshIntervalSeconds = kDefaultRefreshIntervalSeconds);

        ~PasswordKeySource();

        PasswordKeySource(const PasswordKeySource&) = delete;
        PasswordKeySource& operator=(const PasswordKeySource&) = delete;

        /**
         * @brief Re-read the password file and re-derive the key.
         *
         * Always re-reads when called (the background watcher decides separately whether calling
         * this is warranted -- see the class comment). Guarded against a concurrent rewrite the
         * same way Keystore::reload() is: the file's content hash is captured before and after
         * reading, and the read is retried (a few times, briefly) if they don't match.
         *
         * @return true if a usable key is cached after this call, false otherwise (missing,
         *         unreadable, invalid content, an unstable/torn read across every retry, or an
         *         OpenSSL-level HKDF failure). false always means currentKey() will return
         *         nullopt until the next successful reload.
         */
        bool reload();

        /**
         * @return The cached derived key (32 bytes), or nullopt if the password file is missing,
         *         unreadable, or its content fails authd's own password-validity rules.
         */
        std::optional<jwt_profile::v1::SecureBytes> currentKey() const;

    private:
        void watcherLoop();
        void watcherLoopBody();
        void closeWatchFds() noexcept;
        void drainInotifyEvents();
        bool fileLooksChanged();

        std::string m_path;
        mutable std::mutex m_mutex;
        std::optional<jwt_profile::v1::SecureBytes> m_derivedKey;

        int m_refreshIntervalSeconds;
        int m_inotifyFd {-1};
        int m_watchDescriptor {-1};
        int m_stopEventFd {-1};
        std::thread m_watcherThread;

        /// Fallback stop signal, checked every loop iteration independent of m_stopEventFd: if
        /// eventfd() failed at construction (m_stopEventFd stays -1), poll() has no fd to wake it
        /// early, but this flag still gets noticed the next time poll()'s own timeout elapses (at
        /// most m_refreshIntervalSeconds later) -- so the watcher thread is always joinable within
        /// a bounded time, never permanently, which the destructor's join() would otherwise wait
        /// on forever.
        std::atomic<bool> m_stopping {false};

        std::mutex m_reloadMutex;
        bool m_hasBaseline {false};
        std::vector<std::uint8_t> m_lastHash;

        /// Throttles the "authd.pass is unreadable" warning: the watcher retries every
        /// m_refreshIntervalSeconds, so an unreadable file would otherwise flood wazuh-manager.log.
        remoted::common::LogThrottle m_unreadableThrottle;
    };

} // namespace remoted::auth
