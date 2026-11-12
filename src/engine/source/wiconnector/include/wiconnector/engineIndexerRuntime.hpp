// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef WI_ENGINE_INDEXER_RUNTIME_HPP
#define WI_ENGINE_INDEXER_RUNTIME_HPP

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <indexer_client/client.hpp>
#include <indexer_client/runtime.hpp>
#include <indexer_client/runtimeConfig.hpp>
#include <indexer_client/types.hpp>

namespace wiconnector
{

/// The engine's consumer name on its runtime (one Client per process, I154, I189).
constexpr auto ENGINE_INDEXER_CONSUMER {"analysisd"};

/// The engine's buckets (I193, I194).
constexpr auto ENGINE_EVENTS_BUCKET {"events"};
constexpr auto ENGINE_RAW_BUCKET {"raw"};

/**
 * @brief The v1 write options the engine keeps (I187, I188), as `conf` read them, for the `events` and `raw` buckets.
 */
struct EngineWriteOptions
{
    std::uint64_t queueMaxBytes {std::uint64_t {1}
                                 << 26}; ///< `indexer_queue_max_bytes`: each bucket's quota; 0 = global.
    std::uint64_t bulkMaxBytes {std::uint64_t {1} << 23}; ///< `indexer_bulk_max_bytes`, clipped to fit the quota.
    std::chrono::seconds flushInterval {20};              ///< `indexer_flush_interval` → bulk.maxAge.
    std::chrono::seconds maxRetryDelay {15};              ///< `indexer_max_retry_delay` → RetryPolicy.cap.
    std::uint64_t loggerQueueSize {8};                    ///< `indexer_logger_queue_size`: ignored, WARN if not 8.
    std::uint64_t loggerThreads {1};                      ///< `indexer_logger_threads`: ignored, WARN if not 1.
};

/**
 * @brief The `events` and `raw` bucket specs for @p options under @p config (I194, I196): DropNewest, unlimited retry,
 *        `onAmbiguous5xx = Fail`, trusted bodies, weights 2 and 1, the same quota (0 or above the global cap ⇒ the
 * global cap), bulk.maxBytes clipped to quota − RESULT_RESERVE_BYTES.
 *
 * @param warnings Receives one line per value changed or ignored.
 * @return The two specs, or Cause::InvalidConfig when the quota cannot hold a 64 KiB bulk and its reserve.
 */
indexer_client::Outcome<std::vector<indexer_client::BucketSpec>> engineBucketSpecs(
    const EngineWriteOptions& options, const indexer_client::RuntimeConfig& config, std::vector<std::string>& warnings);

/**
 * @brief The engine's indexer_client runtime and its one Client (I37, I189, I191).
 *
 * Every call must come from the thread that called start() (the runtime's owner: the engine's main thread). The stop
 * is in two phases so the engine can place them around its scheduler (I191): beginStop() before the scheduler stops —
 * fixes the shutdown deadline and closes the Client's admission, so a read in flight returns ClientClosed — and
 * finishStop() after it — joins the runtime, which discards what is queued (I186) and logs it in its last summary,
 * then waits for the Client and releases it. finishStop() alone runs both phases; each phase runs once.
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

    /**
     * @brief As start(process, source), with the `events` and `raw` buckets built from @p options (E10b).
     *
     * @param warnings Receives the notes of engineBucketSpecs(), to be logged as WARN.
     */
    indexer_client::Outcome<indexer_client::RuntimeConfig> start(indexer_client::ProcessId process,
                                                                 const indexer_client::IConfigSource& source,
                                                                 const EngineWriteOptions& options,
                                                                 std::vector<std::string>& warnings);

    /// min(Σ bucket quotas, global quota): bounds each bucket's quota in `indexer.queue.usage.percent` (I197,
    /// I218); 0 before start().
    std::uint64_t queueCapacityBytes() const;

    /// The Client (null before start() succeeded and after finishStop()).
    std::shared_ptr<indexer_client::IClient> client() const;

    /// The runtime, for its metrics snapshot (empty before start() succeeded). After finishStop() the reference is
    /// invalid: its snapshot keeps the process-wide query and PIT counters and reads 0 for the rest.
    std::optional<indexer_client::RuntimeRef> runtime() const;

    /// Phase 1: beginShutdown(now + STOP_BUDGET) and requestClose() on the Client.
    void beginStop();

    /// Phase 2: RuntimeOwner::shutdown() (its last summary still sees the Client), then awaitClosed(now), release it.
    void finishStop();

private:
    std::shared_ptr<indexer_client::IClient> m_client;
    std::optional<indexer_client::RuntimeRef> m_runtime;
    std::uint64_t m_queueCapacityBytes {0};
    bool m_started {false};
    bool m_stopBegun {false};
    bool m_stopFinished {false};
};

} // namespace wiconnector

#endif // WI_ENGINE_INDEXER_RUNTIME_HPP
