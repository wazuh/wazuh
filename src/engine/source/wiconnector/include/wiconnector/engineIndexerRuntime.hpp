// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef WI_ENGINE_INDEXER_RUNTIME_HPP
#define WI_ENGINE_INDEXER_RUNTIME_HPP

#include <chrono>
#include <memory>
#include <string>

#include <indexer_client/client.hpp>
#include <indexer_client/runtime.hpp>
#include <indexer_client/runtimeConfig.hpp>
#include <indexer_client/types.hpp>

namespace wiconnector
{

/// The engine's consumer name on its runtime (one Client per process, I154, I189).
constexpr auto ENGINE_INDEXER_CONSUMER {"analysisd"};

/**
 * @brief The engine's indexer_client runtime and its one Client (I37, I189, I191).
 *
 * Every call must come from the thread that called start() (the runtime's owner: the engine's main thread). The stop
 * is in two phases so the engine can place them around its scheduler (I191): beginStop() before the scheduler stops —
 * fixes the shutdown deadline and closes the Client's admission, so a read in flight returns ClientClosed — and
 * finishStop() after it — waits for the Client without draining (I186) and joins the runtime. finishStop() alone runs
 * both phases; each phase runs once.
 */
class EngineIndexerRuntime final
{
public:
    /// How long the stop may take in all (I186: queued work is discarded, nothing is drained).
    static constexpr std::chrono::milliseconds STOP_BUDGET {3000};

    EngineIndexerRuntime() = default;
    ~EngineIndexerRuntime();
    EngineIndexerRuntime(const EngineIndexerRuntime&) = delete;
    EngineIndexerRuntime& operator=(const EngineIndexerRuntime&) = delete;

    /**
     * @brief Validates the configuration, starts the runtime and creates the Client `analysisd` with no buckets.
     *
     * @return Cause::None, or the cause with its reason (the runtime is left stopped).
     */
    indexer_client::Outcome<indexer_client::RuntimeConfig> start(indexer_client::ProcessId process,
                                                                 const indexer_client::IConfigSource& source);

    /// The Client (null before start() succeeded and after finishStop()).
    std::shared_ptr<indexer_client::IClient> client() const;

    /// Phase 1: beginShutdown(now + STOP_BUDGET) and requestClose() on the Client.
    void beginStop();

    /// Phase 2: awaitClosed(now) on the Client, release it, and RuntimeOwner::shutdown().
    void finishStop();

private:
    std::shared_ptr<indexer_client::IClient> m_client;
    bool m_started {false};
    bool m_stopBegun {false};
    bool m_stopFinished {false};
};

} // namespace wiconnector

#endif // WI_ENGINE_INDEXER_RUNTIME_HPP
