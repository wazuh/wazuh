// SPDX-License-Identifier: AGPL-3.0-or-later
#include <wiconnector/engineIndexerRuntime.hpp>

#include <algorithm>
#include <exception>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

#include <base/logging.hpp>
#include <fmt/format.h>

namespace wiconnector
{

namespace
{

/// Overwrites the string's bytes before clearing it (best effort, I55).
void wipe(std::string& secret) noexcept
{
    volatile char* bytes = secret.data();
    for (std::size_t i = 0; i < secret.size(); ++i)
    {
        bytes[i] = '\0';
    }
    secret.clear();
}

/// Wipes the local copy of the password on every exit of start().
struct CredentialsWiper final
{
    indexer_client::Credentials& credentials;
    ~CredentialsWiper() { wipe(credentials.password); }
};

/// The engine's source with the credentials read once: the provider (the keystore) is not asked again by the library.
class PinnedCredentialsSource final : public indexer_client::IConfigSource
{
public:
    PinnedCredentialsSource(const indexer_client::IConfigSource& inner, const indexer_client::Credentials& credentials)
        : m_inner(inner)
        , m_credentials(credentials)
    {
    }

    std::optional<std::string> raw(std::string_view key) const override { return m_inner.raw(key); }
    std::vector<std::string> keysWithPrefix(std::string_view prefix) const override
    {
        return m_inner.keysWithPrefix(prefix);
    }
    std::optional<std::string> problem(std::string_view key) const override { return m_inner.problem(key); }
    std::string indexerSectionJson() const override { return m_inner.indexerSectionJson(); }
    indexer_client::Credentials credentials() const override { return m_credentials; }

private:
    const indexer_client::IConfigSource& m_inner;
    const indexer_client::Credentials& m_credentials;
};

/// The smallest bulk the engine accepts (`analysisd.indexer_bulk_max_bytes`, 64 KiB): a quota must hold it and its
/// reserve (I196).
constexpr std::uint64_t MIN_BULK_MAX_BYTES {std::uint64_t {1} << 16};
/// The two keys a bucket's quota can come from.
constexpr const char* QUEUE_MAX_BYTES_KEY {"analysisd.indexer_queue_max_bytes"};
constexpr const char* GLOBAL_QUOTA_KEY {"analysisd.indexer_client_global_quota_bytes"};
/// `events` is served twice as often as `raw` on the shared transport (I182, I194).
constexpr std::uint32_t EVENTS_WEIGHT {2};
constexpr std::uint32_t RAW_WEIGHT {1};
/// The v1 logger defaults: any other value is reported as ignored (I187).
constexpr std::uint64_t DEFAULT_LOGGER_QUEUE_SIZE {8};
constexpr std::uint64_t DEFAULT_LOGGER_THREADS {1};

template<class T, class U>
indexer_client::Outcome<T> failureFrom(const indexer_client::Outcome<U>& outcome)
{
    return indexer_client::Outcome<T>::failure(outcome.cause, outcome.reason, outcome.httpStatus);
}

/// What a successful start leaves to EngineIndexerRuntime.
struct Started final
{
    std::shared_ptr<indexer_client::IClient> client;
    std::uint64_t queueCapacityBytes {0};
};

/// Both start() overloads: without @p options the Client has no buckets (E10a).
indexer_client::Outcome<indexer_client::RuntimeConfig> startRuntime(indexer_client::ProcessId process,
                                                                    const indexer_client::IConfigSource& source,
                                                                    const EngineWriteOptions* options,
                                                                    std::vector<std::string>* warnings,
                                                                    Started& out)
{
    using Result = indexer_client::Outcome<indexer_client::RuntimeConfig>;

    indexer_client::Credentials credentials;
    const CredentialsWiper wiper {credentials};
    try
    {
        credentials = source.credentials();
    }
    catch (const std::exception& e)
    {
        return Result::failure(indexer_client::Cause::InvalidConfig,
                               std::string("cannot read the indexer credentials from the keystore: ") + e.what());
    }
    catch (...)
    {
        return Result::failure(indexer_client::Cause::InvalidConfig,
                               "cannot read the indexer credentials from the keystore: unknown error");
    }
    const PinnedCredentialsSource pinned {source, credentials};

    auto config = indexer_client::RuntimeConfig::from(process, pinned);
    if (!config.ok())
    {
        return config;
    }

    // The buckets need the global quota, so they are built from the validated configuration, before the runtime
    // starts: a quota that cannot hold a bulk fails the start without a runtime (I196).
    std::vector<indexer_client::BucketSpec> buckets;
    if (options != nullptr)
    {
        auto specs = engineBucketSpecs(*options, config.value, *warnings);
        if (!specs.ok())
        {
            return failureFrom<indexer_client::RuntimeConfig>(specs);
        }
        buckets = std::move(specs.value);
    }

    auto started = indexer_client::RuntimeOwner::start(process, pinned);
    if (!started.ok())
    {
        return failureFrom<indexer_client::RuntimeConfig>(started);
    }

    std::uint64_t quotas {0};
    for (const auto& bucket : buckets)
    {
        quotas += bucket.quotaBytes;
    }

    auto client = started.value.client(ENGINE_INDEXER_CONSUMER, std::move(buckets));
    if (!client.ok() || !client.value)
    {
        indexer_client::RuntimeOwner::beginShutdown(std::chrono::steady_clock::now());
        indexer_client::RuntimeOwner::shutdown();
        return client.ok() ? Result::failure(indexer_client::Cause::InvalidState, "the runtime returned no Client")
                           : failureFrom<indexer_client::RuntimeConfig>(client);
    }

    out.client = std::move(client.value);
    out.queueCapacityBytes = std::min(quotas, config.value.globalQuotaBytes);
    return config;
}

} // namespace

indexer_client::Outcome<std::vector<indexer_client::BucketSpec>> engineBucketSpecs(
    const EngineWriteOptions& options, const indexer_client::RuntimeConfig& config, std::vector<std::string>& warnings)
{
    using Result = indexer_client::Outcome<std::vector<indexer_client::BucketSpec>>;

    // I188: one quota for both buckets; 0 is the v1's "no limit", which the runtime's cap bounds.
    std::uint64_t quota = options.queueMaxBytes == 0 ? config.globalQuotaBytes : options.queueMaxBytes;
    // The key whose value the quota ends up with, for the error below.
    const char* quotaKey = options.queueMaxBytes == 0 ? GLOBAL_QUOTA_KEY : QUEUE_MAX_BYTES_KEY;
    if (quota > config.globalQuotaBytes)
    {
        warnings.push_back(fmt::format("{} ({}) is above {} ({}): using {}",
                                       QUEUE_MAX_BYTES_KEY,
                                       quota,
                                       GLOBAL_QUOTA_KEY,
                                       config.globalQuotaBytes,
                                       config.globalQuotaBytes));
        quota = config.globalQuotaBytes;
        quotaKey = GLOBAL_QUOTA_KEY;
    }
    if (quota < MIN_BULK_MAX_BYTES + indexer_client::RESULT_RESERVE_BYTES)
    {
        return Result::failure(indexer_client::Cause::InvalidConfig,
                               fmt::format("{} ({}) cannot hold one bulk of {} bytes and its {}-byte reserve: the "
                                           "minimum is {}",
                                           quotaKey,
                                           quota,
                                           MIN_BULK_MAX_BYTES,
                                           indexer_client::RESULT_RESERVE_BYTES,
                                           MIN_BULK_MAX_BYTES + indexer_client::RESULT_RESERVE_BYTES));
    }

    std::uint64_t bulkMaxBytes = options.bulkMaxBytes;
    if (bulkMaxBytes + indexer_client::RESULT_RESERVE_BYTES > quota)
    {
        bulkMaxBytes = quota - indexer_client::RESULT_RESERVE_BYTES;
        warnings.push_back(fmt::format("analysisd.indexer_bulk_max_bytes ({}) plus the {}-byte reserve of an operation "
                                       "does not fit in the queue quota ({}): using {}",
                                       options.bulkMaxBytes,
                                       indexer_client::RESULT_RESERVE_BYTES,
                                       quota,
                                       bulkMaxBytes));
    }

    if (options.maxRetryDelay <= std::chrono::seconds::zero())
    {
        return Result::failure(indexer_client::Cause::InvalidConfig, "analysisd.indexer_max_retry_delay must be > 0");
    }
    if (options.flushInterval <= std::chrono::seconds::zero())
    {
        return Result::failure(indexer_client::Cause::InvalidConfig, "analysisd.indexer_flush_interval must be > 0");
    }

    if (options.loggerQueueSize != DEFAULT_LOGGER_QUEUE_SIZE)
    {
        warnings.push_back(fmt::format("analysisd.indexer_logger_queue_size ({}) is ignored: the indexer client has "
                                       "no error logger queue",
                                       options.loggerQueueSize));
    }
    if (options.loggerThreads != DEFAULT_LOGGER_THREADS)
    {
        warnings.push_back(fmt::format("analysisd.indexer_logger_threads ({}) is ignored: the indexer client has no "
                                       "error logger threads",
                                       options.loggerThreads));
    }

    indexer_client::BucketSpec events;
    events.name = ENGINE_EVENTS_BUCKET;
    events.weight = EVENTS_WEIGHT;
    events.quotaBytes = static_cast<std::size_t>(quota);
    // Unlimited retry (I6): the queue, not the attempts, bounds what an outage holds; a full quota drops the newest
    // event and the router never waits (I182).
    events.retry.maxAttempts = std::nullopt;
    events.retry.maxDuration = std::nullopt;
    events.retry.cap = std::chrono::duration_cast<indexer_client::Duration>(options.maxRetryDelay);
    events.retry.base = std::min(events.retry.base, events.retry.cap);
    events.overflow.kind = indexer_client::Overflow::Kind::DropNewest;
    events.bulk.maxBytes = static_cast<std::size_t>(bulkMaxBytes);
    events.bulk.maxAge = std::chrono::duration_cast<indexer_client::Duration>(options.flushInterval);
    // The v1 cut a bulk only by bytes and by time: no document count closes one (the library only requires > 0).
    events.bulk.maxDocs = std::numeric_limits<std::size_t>::max();
    // Data streams without `_id`: resending an ambiguous 5xx would duplicate (I105). The engine only sends compact
    // JSON from json::Json::str(), which escapes every '\n' (I125).
    events.onAmbiguous5xx = indexer_client::AmbiguousPolicy::Fail;
    events.trustedBodies = true;

    auto raw = events;
    raw.name = ENGINE_RAW_BUCKET;
    raw.weight = RAW_WEIGHT;

    return Result::success({std::move(events), std::move(raw)});
}

EngineIndexerRuntime::~EngineIndexerRuntime()
{
    try
    {
        finishStop();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("[indexer-client] Unexpected error while stopping the runtime: {}", e.what());
    }
    catch (...)
    {
        LOG_ERROR("[indexer-client] Unexpected error while stopping the runtime");
    }
}

indexer_client::Outcome<indexer_client::RuntimeConfig>
EngineIndexerRuntime::start(indexer_client::ProcessId process, const indexer_client::IConfigSource& source)
{
    if (m_started)
    {
        return indexer_client::Outcome<indexer_client::RuntimeConfig>::failure(
            indexer_client::Cause::InvalidState, "the engine's indexer runtime was already started");
    }
    Started started;
    auto config = startRuntime(process, source, nullptr, nullptr, started);
    if (config.ok())
    {
        m_client = std::move(started.client);
        m_queueCapacityBytes = started.queueCapacityBytes;
        m_started = true;
    }
    return config;
}

indexer_client::Outcome<indexer_client::RuntimeConfig>
EngineIndexerRuntime::start(indexer_client::ProcessId process,
                            const indexer_client::IConfigSource& source,
                            const EngineWriteOptions& options,
                            std::vector<std::string>& warnings)
{
    if (m_started)
    {
        return indexer_client::Outcome<indexer_client::RuntimeConfig>::failure(
            indexer_client::Cause::InvalidState, "the engine's indexer runtime was already started");
    }
    Started started;
    auto config = startRuntime(process, source, &options, &warnings, started);
    if (config.ok())
    {
        m_client = std::move(started.client);
        m_queueCapacityBytes = started.queueCapacityBytes;
        m_started = true;
    }
    return config;
}

std::uint64_t EngineIndexerRuntime::queueCapacityBytes() const
{
    return m_queueCapacityBytes;
}

std::shared_ptr<indexer_client::IClient> EngineIndexerRuntime::client() const
{
    return m_client;
}

void EngineIndexerRuntime::beginStop()
{
    if (!m_started || m_stopBegun)
    {
        return;
    }
    m_stopBegun = true;
    indexer_client::RuntimeOwner::beginShutdown(std::chrono::steady_clock::now() + STOP_BUDGET);
    if (m_client)
    {
        m_client->requestClose();
    }
}

void EngineIndexerRuntime::finishStop()
{
    if (!m_started || m_stopFinished)
    {
        return;
    }
    beginStop();
    m_stopFinished = true;

    if (m_client)
    {
        // No drain (I186): whatever is still queued is discarded now.
        const auto closed = m_client->awaitClosed(std::chrono::steady_clock::now());
        if (!closed.ok())
        {
            LOG_WARNING("[indexer-client] Closing the engine's client: {}: {}",
                        indexer_client::toString(closed.cause),
                        closed.reason.c_str());
        }
        m_client.reset();
    }

    const auto cause = indexer_client::RuntimeOwner::shutdown();
    if (cause != indexer_client::Cause::None)
    {
        LOG_ERROR("[indexer-client] The runtime refused to shut down: {}", indexer_client::toString(cause));
    }
}

} // namespace wiconnector
