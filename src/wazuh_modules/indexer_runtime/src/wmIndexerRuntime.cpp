/*
 * Wazuh modulesd indexer client runtime bridge
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmIndexerRuntime.hpp"
#include "wm_indexer_runtime_api.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstring>
#include <exception>
#include <mutex>
#include <string>
#include <utility>

#include "indexer_client/keyValueConfigSource.hpp"
#include "indexer_client/runtime.hpp"
#include "indexer_client/runtimeConfig.hpp"
#include "indexer_client/types.hpp"
#include "keyStore.hpp"

#ifndef ARGV0
#define ARGV0 "wazuh-manager-modulesd"
#endif

namespace
{
    /// Tag of every line the library logs through modulesd.
    constexpr const char* LOG_TAG = ARGV0 ":indexer-client";

    /// Same value as LOGLEVEL_ERROR (shared/include/defs.h), the level mtLoggingFunctionsWrapper logs as ERROR.
    constexpr int LOG_LEVEL_ERROR = 3;

    /// The log function wmir_start() received: the catch-all handlers that have no reason buffer report through it.
    /// Trivially destructible, so it stays usable during exit().
    std::atomic<wmir_log_fn> g_log {nullptr}; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

    /// One ERROR line through the saved log function; nothing without one. Never throws.
    void logError(const char* func, const char* fmt, ...) noexcept
    {
        const auto log = g_log.load();
        if (log == nullptr)
        {
            return;
        }
        va_list args;
        va_start(args, fmt);
        log(LOG_LEVEL_ERROR, LOG_TAG, __FILE__, __LINE__, func, fmt, args);
        va_end(args);
    }

    /// The published RuntimeRef. Heap-allocated and never deleted, on purpose: a module thread whose join
    /// expired in wm_shutdown_run() is still alive while exit() runs the static destructors, and may still call
    /// wmir_ref() or read the reference. A static object would be destroyed under it; this one stays readable and,
    /// after shutdown(), reports !valid().
    indexer_client::RuntimeRef& publishedRef()
    {
        static auto* const ref = new indexer_client::RuntimeRef; // NOLINT(cppcoreguidelines-owning-memory)
        return *ref;
    }

    indexer_client::Credentials keystoreCredentials()
    {
        indexer_client::Credentials credentials;
        credentials.user = Keystore::get("indexer", "username");
        credentials.password = Keystore::get("indexer", "password");
        return credentials;
    }

    /// Overwrites the string's bytes before clearing it (best effort).
    void wipe(std::string& secret) noexcept
    {
        volatile char* bytes = secret.data();
        for (std::size_t i = 0; i < secret.size(); ++i)
        {
            bytes[i] = '\0';
        }
        secret.clear();
    }

    struct CredentialsWiper final
    {
        indexer_client::Credentials& credentials;
        ~CredentialsWiper()
        {
            wipe(credentials.password);
        }
    };

    struct State final
    {
        std::mutex mutex;
        std::string optionsText;
        std::string indexerJson;
        bool configured {false};
        std::atomic<bool> running {false};
        wmir::CredentialReader reader {keystoreCredentials};
    };

    /// Heap-allocated and never deleted, for the same reason as publishedRef(): a module thread that outlives its
    /// join may still take the mutex or read the flags while exit() runs the static destructors.
    State& state()
    {
        static auto* const s = new State; // NOLINT(cppcoreguidelines-owning-memory)
        return *s;
    }

    void setReason(char* reason, size_t reasonLen, const std::string& text) noexcept
    {
        if (reason == nullptr || reasonLen == 0)
        {
            return;
        }
        const auto n = std::min(text.size(), reasonLen - 1);
        std::memcpy(reason, text.data(), n);
        reason[n] = '\0';
    }

    void clearReason(char* reason, size_t reasonLen) noexcept
    {
        if (reason != nullptr && reasonLen > 0)
        {
            reason[0] = '\0';
        }
    }

    template<class T>
    std::string describe(const indexer_client::Outcome<T>& outcome)
    {
        return std::string(indexer_client::toString(outcome.cause)) + ": " + outcome.reason;
    }

    /// Joins a running runtime (owner thread). Caller holds the state mutex.
    void shutdownLocked(State& s, bool fixDeadlineNow)
    {
        if (!s.running.load())
        {
            return;
        }
        if (fixDeadlineNow)
        {
            indexer_client::RuntimeOwner::beginShutdown(std::chrono::steady_clock::now());
        }
        const auto cause = indexer_client::RuntimeOwner::shutdown();
        // A refused shutdown (UsageError: not the owner thread) leaves the runtime and the published reference alive.
        if (!indexer_client::RuntimeOwner::running())
        {
            s.running.store(false);
        }
        else
        {
            logError(__func__,
                     "The indexer client runtime refused to shut down (%s); it keeps running.",
                     indexer_client::toString(cause));
        }
    }
} // namespace

namespace wmir
{
    void setCredentialReaderForTests(CredentialReader reader)
    {
        auto& s = state();
        std::lock_guard<std::mutex> lock(s.mutex);
        s.reader = reader ? std::move(reader) : CredentialReader {keystoreCredentials};
    }

    void resetForTests()
    {
        auto& s = state();
        std::lock_guard<std::mutex> lock(s.mutex);
        shutdownLocked(s, true);
        s.optionsText.clear();
        s.indexerJson.clear();
        s.configured = false;
        s.reader = keystoreCredentials;
    }
} // namespace wmir

extern "C"
{
    int wmir_configure(
        const char* options_text, const char* indexer_json, int has_consumer, char* reason, size_t reason_len)
    {
        clearReason(reason, reason_len);
        try
        {
            auto& s = state();
            std::lock_guard<std::mutex> lock(s.mutex);
            if (has_consumer == 0)
            {
                s.optionsText.clear();
                s.indexerJson.clear();
                s.configured = false;
                return 0;
            }

            std::string text = options_text != nullptr ? options_text : "";
            std::string json = indexer_json != nullptr ? indexer_json : "{}";

            auto source = indexer_client::KeyValueConfigSource::parse(text, json, indexer_client::Credentials {});
            if (!source.ok())
            {
                setReason(reason, reason_len, describe(source));
                return -1;
            }
            auto config = indexer_client::RuntimeConfig::from(indexer_client::ProcessId::Modulesd, source.value);
            if (!config.ok())
            {
                setReason(reason, reason_len, describe(config));
                return -1;
            }

            s.optionsText = std::move(text);
            s.indexerJson = std::move(json);
            s.configured = true;
            return 0;
        }
        catch (const std::exception& e)
        {
            setReason(
                reason, reason_len, std::string("unexpected error while validating the configuration: ") + e.what());
        }
        catch (...)
        {
            setReason(reason, reason_len, "unexpected error while validating the configuration");
        }
        return -1;
    }

    int wmir_start(wmir_log_fn log, char* reason, size_t reason_len)
    {
        clearReason(reason, reason_len);
        try
        {
            auto& s = state();
            std::lock_guard<std::mutex> lock(s.mutex);
            if (!s.configured)
            {
                return 0;
            }
            if (s.running.load())
            {
                setReason(reason, reason_len, "the indexer client runtime is already running");
                return -1;
            }

            g_log.store(log);

            // Only valid while no runtime runs: installed before start().
            if (log != nullptr)
            {
                indexer_client::setLogFunction([log](const int level,
                                                     const char* /*tag*/,
                                                     const char* file,
                                                     const int line,
                                                     const char* func,
                                                     const char* msg,
                                                     va_list args)
                                               { log(level, LOG_TAG, file, line, func, msg, args); });
            }
            else
            {
                indexer_client::setLogFunction({});
            }

            indexer_client::Credentials credentials;
            const CredentialsWiper wiper {credentials};
            try
            {
                credentials = s.reader();
            }
            catch (const std::exception& e)
            {
                setReason(reason,
                          reason_len,
                          std::string("cannot read the indexer credentials from the keystore: ") + e.what());
                return -1;
            }
            catch (...)
            {
                setReason(reason, reason_len, "cannot read the indexer credentials from the keystore: unknown error");
                return -1;
            }

            // KeyValueConfigSource takes its own copy and wipes it on destruction; the local copy is wiped by
            // the guard on every exit.
            auto source = indexer_client::KeyValueConfigSource::parse(s.optionsText, s.indexerJson, credentials);
            if (!source.ok())
            {
                setReason(reason, reason_len, describe(source));
                return -1;
            }

            auto started = indexer_client::RuntimeOwner::start(indexer_client::ProcessId::Modulesd, source.value);
            if (!started.ok())
            {
                setReason(reason, reason_len, describe(started));
                return -1;
            }

            // Published only once the result is known to be good.
            publishedRef() = std::move(started.value);
            s.running.store(true);
            return 0;
        }
        catch (const std::exception& e)
        {
            setReason(reason, reason_len, std::string("unexpected error while starting the runtime: ") + e.what());
        }
        catch (...)
        {
            setReason(reason, reason_len, "unexpected error while starting the runtime");
        }
        return -1;
    }

    const void* wmir_ref(void)
    {
        try
        {
            return state().running.load() ? &publishedRef() : nullptr;
        }
        catch (...)
        {
            logError(__func__, "Unexpected error while reading the indexer client runtime reference.");
            return nullptr;
        }
    }

    void wmir_begin_shutdown(long remaining_ms)
    {
        try
        {
            auto& s = state();
            std::lock_guard<std::mutex> lock(s.mutex);
            if (!s.running.load())
            {
                return;
            }
            indexer_client::RuntimeOwner::beginShutdown(std::chrono::steady_clock::now() +
                                                        std::chrono::milliseconds(std::max(remaining_ms, 0L)));
        }
        catch (...)
        {
            // Nothing crosses the C boundary; the runtime keeps its previous deadline, if any.
            logError(__func__, "Unexpected error while fixing the indexer client shutdown deadline.");
        }
    }

    void wmir_shutdown(void)
    {
        try
        {
            auto& s = state();
            std::lock_guard<std::mutex> lock(s.mutex);
            shutdownLocked(s, false);
        }
        catch (...)
        {
            // Nothing crosses the C boundary.
            logError(__func__, "Unexpected error while shutting the indexer client runtime down.");
        }
    }
}
