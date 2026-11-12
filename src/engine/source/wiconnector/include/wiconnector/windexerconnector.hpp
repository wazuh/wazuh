// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _WINDEXER_CONNECTOR_HPP
#define _WINDEXER_CONNECTOR_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <indexer_client/client.hpp>
#include <indexer_client/metrics.hpp>
#include <wiconnector/iwindexerconnector.hpp>

namespace wiconnector
{

/// A failed remote configuration read (getEngineRemoteConfig()): the search failed, or its answer holds no single
/// settings document with an `engine` object. what() is the whole message; callers catch std::exception.
class RemoteConfigError : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

/// The `<indexer>` section of a standalone engine (`hosts`, `ssl`), as the indexer client reads it.
struct Config
{
    std::vector<std::string> hosts; ///< The list of hosts to connect to. i.e. ["https://localhost:9200"]

    struct
    {
        std::vector<std::string> cacert; ///< Path to the CA bundle file. '/certificate_authorities'
        std::string cert;                ///< The certificate to connect to OpenSearch. '/certificate'
        std::string key;                 ///< The key to connect to OpenSearch.'/key'
        bool verifyCertificates {true};  ///< Verify the server certificate. '/verify_certificates'
    } ssl;                               ///< SSL options. '/ssl'

    std::string toJson() const;
};

/**
 * @brief The Engine's writes and its remote configuration read, on the Engine's indexer_client Client (E10b).
 *
 * index() posts each event to the `events` bucket, or to `raw` for RAW_EVENTS_INDEX (I193), with the index and the
 * body moved into the operation and no lock: the writers are fixed in the constructor. A refused post is logged on the
 * edge and counted only by the library (`rejected` in the bucket's metrics). shutdown() releases the writers and the
 * reader; an index() after it discards the event and counts it in getDroppedEvents(). No index() may run concurrently
 * with shutdown() (I196b): the router and tester workers are joined before the indexer stops.
 *
 * The three queue metrics and the per-bucket ones (getBucketMetric()) read one cached snapshot of Client::metrics(),
 * refreshed at most once per second (I197).
 */
class WIndexerConnector : public IWIndexerConnector
{
public:
    /// How long a metrics snapshot serves the getters (one scrape reads all three).
    static constexpr std::chrono::milliseconds METRICS_TTL {1000};

    WIndexerConnector() = delete;
    ~WIndexerConnector() override;

    /**
     * @brief Writes and reads through the engine's Client (E10b, I193, I196, I196b): index() posts to the `events` or
     *        `raw` bucket without a lock; shutdown() releases the writers and the reader. No index() may run
     *        concurrently with shutdown(): the router and tester workers are joined before the indexer stops.
     *
     * @param client The engine's Client with the `events` and `raw` buckets. Must not be null.
     * @param requestTimeout The runtime's `request_timeout_ms` (remote configuration reads).
     * @param queueCapacityBytes min(Σ bucket quotas, global quota): the budget the buckets share, the second term of
     *        getQueueUsagePercent() (I197, I218); 0 reports 0.0.
     * @throws std::runtime_error if @p client is null or lacks a bucket
     */
    WIndexerConnector(std::shared_ptr<indexer_client::IClient> client,
                      std::chrono::milliseconds requestTimeout,
                      std::uint64_t queueCapacityBytes);

    /**
     * @copydoc IWIndexerConnector::index
     */
    void index(std::string index, std::string data) override;

    /**
     * @copydoc IWIndexerConnector::getEngineRemoteConfig
     */
    json::Json getEngineRemoteConfig() override;

    /**
     * @brief Σ `retainedBytes` of `events` and `raw` (I195); 0 once shut down.
     */
    uint64_t getQueueSize() override;

    /**
     * @brief Σ `dropped` + `failed` + `rejected` of `events` and `raw` (I185), plus the events discarded after
     *        shutdown(). After shutdown() the bucket part is the last snapshot taken.
     */
    uint64_t getDroppedEvents() override;

    /**
     * @brief max(the fullest bucket, the shared budget) × 100, capped at 100 (I197, I218): max over `events` and
     *        `raw` of `charge` / `quotaBytes`, and Σ `charge` / @p queueCapacityBytes. 100 means a bucket or the global
     *        budget is full, i.e. new events are being dropped; a bucket without a quota counts as 0. 0.0 once shut
     *        down or without a capacity.
     */
    double getQueueUsagePercent() override;

    /**
     * @brief The names of the per-bucket metrics getBucketMetric() serves, with their kind: the library's catalog for
     *        the `events` and `raw` buckets of the engine's Client, `indexer_client.bucket.analysisd.<bucket>.<field>`
     *        (the names of a snapshot with no values: fixed, every member of every closed set included).
     */
    static std::vector<std::pair<std::string, indexer_client::MetricKind>> bucketMetricNames();

    /**
     * @brief The value of @p name, one of bucketMetricNames(), in the same cached snapshot the three getters read;
     *        0 for any other name or before the first snapshot. After shutdown() the last snapshot taken.
     */
    double getBucketMetric(const std::string& name);

    /**
     * @brief Releases the writers and the Client. Must not run concurrently with index() (I196b).
     *
     * The engine calls it after the Client's requestClose() (EngineIndexerRuntime::beginStop()), so a remote
     * configuration read in flight returns ClientClosed.
     */
    void shutdown();

private:
    /// The bucket sums of one Client::metrics() snapshot.
    struct Totals final
    {
        std::uint64_t retainedBytes {0};
        std::uint64_t dropped {0};
        double usagePercent {0.0}; ///< max(fullest bucket, Σ charge / capacity) × 100, uncapped (I218).
    };

    /// The cached totals, refreshed when older than METRICS_TTL and the Client is still held.
    Totals totals();

    /// Takes a new snapshot into m_totals and m_bucketValues when the cache is older than METRICS_TTL and the Client
    /// is still held. Under m_metricsMutex.
    void refreshLocked();

    std::shared_ptr<indexer_client::IWriter> m_events; ///< Fixed until shutdown(); read without a lock.
    std::shared_ptr<indexer_client::IWriter> m_raw;    ///< Fixed until shutdown(); read without a lock.
    std::atomic<bool> m_closed {false};                ///< Set by shutdown() before it releases the writers.
    std::atomic<bool> m_refusing {false};              ///< A post was refused and none accepted since (log edge).
    std::atomic<std::uint64_t> m_discardedAfterShutdown {0};

    std::mutex m_mutex;                                ///< Guards m_client (copied out, never called under it).
    std::shared_ptr<indexer_client::IClient> m_client; ///< Reads and metrics; null after shutdown().
    std::chrono::milliseconds m_requestTimeout;
    std::uint64_t m_queueCapacityBytes;

    std::mutex m_metricsMutex; ///< Guards the cache and serializes its refresh (one snapshot per TTL).
    Totals m_totals;
    std::unordered_map<std::string, double> m_bucketValues; ///< The bucketMetricNames() values of the snapshot.
    std::chrono::steady_clock::time_point m_totalsAt {};
    bool m_hasTotals {false};
};
}; // namespace wiconnector

#endif // _WINDEXER_CONNECTOR_HPP
