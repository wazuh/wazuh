// SPDX-License-Identifier: AGPL-3.0-or-later
#include <wiconnector/engineIndexerRuntime.hpp>

#include <exception>
#include <utility>
#include <vector>

#include <base/logging.hpp>

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

template<class T, class U>
indexer_client::Outcome<T> failureFrom(const indexer_client::Outcome<U>& outcome)
{
    return indexer_client::Outcome<T>::failure(outcome.cause, outcome.reason, outcome.httpStatus);
}

} // namespace

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
    using Result = indexer_client::Outcome<indexer_client::RuntimeConfig>;

    if (m_started)
    {
        return Result::failure(indexer_client::Cause::InvalidState, "the engine's indexer runtime was already started");
    }

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

    auto started = indexer_client::RuntimeOwner::start(process, pinned);
    if (!started.ok())
    {
        return failureFrom<indexer_client::RuntimeConfig>(started);
    }

    auto client = started.value.client(ENGINE_INDEXER_CONSUMER, {});
    if (!client.ok() || !client.value)
    {
        indexer_client::RuntimeOwner::beginShutdown(std::chrono::steady_clock::now());
        indexer_client::RuntimeOwner::shutdown();
        return client.ok() ? Result::failure(indexer_client::Cause::InvalidState, "the runtime returned no Client")
                           : failureFrom<indexer_client::RuntimeConfig>(client);
    }

    m_client = std::move(client.value);
    m_started = true;
    return config;
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
