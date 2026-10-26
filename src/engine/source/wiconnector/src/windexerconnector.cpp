// SPDX-License-Identifier: AGPL-3.0-or-later
#include <algorithm>
#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <json.hpp>

#include <base/logging.hpp>

#include <wiconnector/engineIndexerRuntime.hpp>
#include <wiconnector/windexerconnector.hpp>

namespace wiconnector
{

namespace
{

constexpr std::size_t SINGLE_RESULT_SIZE {1};                     ///< Size for single result queries
constexpr std::string_view REMOTE_CONF_INDEX {".wazuh-settings"}; ///< remote conf index name

size_t getTotalHits(const nlohmann::json& hits)
{
    if (!hits.contains("total") || !hits["total"].is_object())
    {
        throw std::runtime_error("Hits object is invalid or does not contain total hits");
    }

    const auto& total = hits["total"];
    if (total.is_object() && total.contains("value"))
    {
        return total["value"].get<size_t>();
    }
    else if (total.is_number())
    {
        return total.get<size_t>();
    }
    else
    {
        throw std::runtime_error("Total hits format is unrecognized");
    }
}

/// How far past the page deadline the remote configuration call may last: the library lets an attempt with the whole
/// budget overrun the page by its 1 s grace before it reports the node, and the call must not cut that short.
constexpr std::chrono::milliseconds REMOTE_CONF_DEADLINE_MARGIN {5000};
/// While no node is usable yet (before the first probe round), the most a read waits for one, as the content adapter's
/// probeDeadline does (I158b): it must not hold a scheduler thread for a whole request timeout.
constexpr std::chrono::milliseconds REMOTE_CONF_NODE_WAIT {10000};

/// The remote configuration query, the same body the v1 connector sent.
nlohmann::json remoteConfigBody()
{
    nlohmann::json body;
    body["size"] = SINGLE_RESULT_SIZE;
    body["track_total_hits"] = true;
    body["stored_fields"] = nlohmann::json::array();
    body["query"] = {{"match_all", nlohmann::json::object()}};
    body["_source"] = {{"includes", {"engine"}}, {"excludes", nlohmann::json::array()}};
    return body;
}

/// The `engine` object of the one settings document in @p hits (the `hits` object of a search response).
json::Json engineConfigFromHits(const nlohmann::json& hits)
{
    size_t totalHits = getTotalHits(hits);

    if (totalHits == 0)
    {
        throw RemoteConfigError("Remote settings document not found");
    }

    if (totalHits > 1)
    {
        throw RemoteConfigError("Multiple remote settings documents found in index " + std::string(REMOTE_CONF_INDEX)
                                + " (expected 1, got " + std::to_string(totalHits) + ")");
    }

    const auto& hitArray = hits["hits"];
    if (!hitArray.is_array() || hitArray.empty())
    {
        throw RemoteConfigError("No hits returned for remote settings");
    }

    const auto& firstHit = hitArray[0];
    if (!firstHit.contains("_source"))
    {
        throw RemoteConfigError("Remote settings hit does not contain _source");
    }

    const auto& sourceData = firstHit["_source"];
    if (!sourceData.contains("engine") || !sourceData["engine"].is_object())
    {
        throw RemoteConfigError("Remote settings _source.engine missing or invalid");
    }

    return json::Json {sourceData["engine"].dump().c_str()};
}

/// The remote configuration through the engine's Client: one attempt, a page deadline of the request timeout and an
/// immediate failure once every node was probed and none is usable (I190, I190b). Every failure throws.
json::Json remoteConfigFromClient(indexer_client::IClient& reader, std::chrono::milliseconds requestTimeout)
{
    if (const auto why = reader.health().noUsableAfterProbes())
    {
        throw RemoteConfigError(std::string {"Search request failed: no usable indexer node ("} + *why + ")");
    }

    const auto query = reader.query();
    if (!query)
    {
        throw RemoteConfigError(std::string {"Search request failed: "}
                                + indexer_client::toString(indexer_client::Cause::ClientClosed));
    }

    indexer_client::QueryOptions options;
    options.retry.maxAttempts = 1;
    options.pageDeadline = requestTimeout;
    const auto budget = reader.health().anyUsable()
                            ? requestTimeout + REMOTE_CONF_DEADLINE_MARGIN
                            : std::min(requestTimeout + REMOTE_CONF_DEADLINE_MARGIN, REMOTE_CONF_NODE_WAIT);
    const auto deadline = std::chrono::steady_clock::now() + budget;

    const auto outcome = query->search(REMOTE_CONF_INDEX, remoteConfigBody(), options, deadline);
    if (!outcome.ok())
    {
        throw RemoteConfigError(std::string {"Search request failed: "} + indexer_client::toString(outcome.cause)
                                + (outcome.reason.empty() ? "" : ": " + outcome.reason));
    }
    if (!outcome.value.is_object() || !outcome.value.contains("hits"))
    {
        throw RemoteConfigError("Search response does not contain 'hits' field");
    }
    return engineConfigFromHits(outcome.value["hits"]);
}

} // namespace

/****************************************************************************************
 * Config
 ****************************************************************************************/

/*
 * Example:
 * {
 *   "hosts": [
 *     "http://10.2.20.2:9200",
 *     "https://10.2.20.42:9200"
 *   ],
 *   "ssl": {
 *     "certificate_authorities": [
 *       "/var/wazuh-manager/",
 *       "/var/wazuh-manager_cert/"
 *     ],
 *     "certificate": "cert",
 *     "key": "key_example",
 *     "verify_certificates": true
 *   }
 * }
 */
std::string Config::toJson() const
{
    nlohmann::json config {};
    config["hosts"] = hosts;

    // `verify_certificates` is always emitted, so the section states the choice explicitly.
    {
        nlohmann::json sslJson {};
        sslJson["verify_certificates"] = ssl.verifyCertificates;
        if (!ssl.cacert.empty())
        {
            sslJson["certificate_authorities"] = ssl.cacert;
        }
        if (!ssl.cert.empty())
        {
            sslJson["certificate"] = ssl.cert;
        }
        if (!ssl.key.empty())
        {
            sslJson["key"] = ssl.key;
        }
        config["ssl"] = sslJson;
    }

    return config.dump();
}

/****************************************************************************************
 * WIndexerConnector
 ****************************************************************************************/

WIndexerConnector::WIndexerConnector(std::shared_ptr<indexer_client::IClient> client,
                                     std::chrono::milliseconds requestTimeout,
                                     std::uint64_t queueCapacityBytes)
    : m_client(std::move(client))
    , m_requestTimeout(requestTimeout)
    , m_queueCapacityBytes(queueCapacityBytes)
{
    if (!m_client)
    {
        throw std::runtime_error("The indexer client cannot be null");
    }
    m_events = m_client->writer(ENGINE_EVENTS_BUCKET);
    m_raw = m_client->writer(ENGINE_RAW_BUCKET);
    if (!m_events || !m_raw)
    {
        throw std::runtime_error(std::string {"The indexer client has no '"}
                                 + (m_events ? ENGINE_RAW_BUCKET : ENGINE_EVENTS_BUCKET) + "' bucket");
    }
}

WIndexerConnector::~WIndexerConnector() = default;

void WIndexerConnector::shutdown()
{
    LOG_INFO("[indexer-connector] Shutdown initiated");
    m_closed.store(true, std::memory_order_release);
    std::shared_ptr<indexer_client::IClient> client;
    {
        std::lock_guard lock(m_mutex);
        client = std::move(m_client);
        m_events.reset();
        m_raw.reset();
    }
    // The Client is released outside the lock: a remote configuration read in flight keeps its own copy.
    client.reset();
}

void WIndexerConnector::index(std::string index, std::string data)
{
    if (m_closed.load(std::memory_order_acquire))
    {
        m_discardedAfterShutdown.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    auto& writer = index == RAW_EVENTS_INDEX ? *m_raw : *m_events;
    indexer_client::Op op;
    op.kind = indexer_client::Op::Kind::IndexDataStream;
    op.index = std::move(index);
    op.body = std::move(data);
    const auto posted = writer.post(std::move(op));

    // The library counts every refusal (`rejected` in the bucket's metrics): here it is only logged, on the edge.
    if (!posted.accepted)
    {
        if (!m_refusing.exchange(true, std::memory_order_relaxed))
        {
            LOG_WARNING("[indexer-connector] The indexer client refused an event: {}{}{} (further refusals are counted "
                        "in indexer.events.dropped)",
                        indexer_client::toString(posted.cause),
                        posted.reason.empty() ? "" : ": ",
                        posted.reason);
        }
    }
    else if (m_refusing.load(std::memory_order_relaxed) && m_refusing.exchange(false, std::memory_order_relaxed))
    {
        LOG_INFO("[indexer-connector] The indexer client accepts events again");
    }
}

WIndexerConnector::Totals WIndexerConnector::totals()
{
    std::lock_guard metricsLock(m_metricsMutex);
    const auto now = std::chrono::steady_clock::now();
    if (m_hasTotals && now - m_totalsAt < METRICS_TTL)
    {
        return m_totals;
    }

    std::shared_ptr<indexer_client::IClient> client;
    {
        std::lock_guard lock(m_mutex);
        client = m_client;
    }
    if (!client)
    {
        return m_totals; // The last snapshot taken (zeros if none).
    }

    Totals totals;
    std::uint64_t charge {0};
    for (const auto& bucket : client->metrics().buckets)
    {
        totals.retainedBytes += bucket.retainedBytes;
        charge += bucket.charge;
        // I218: each bucket against its own quota (the runtime keeps it <= the global quota); a bucket without a
        // quota adds nothing (no division by zero).
        if (bucket.quotaBytes != 0)
        {
            const auto percent = static_cast<double>(bucket.charge) * 100.0 / static_cast<double>(bucket.quotaBytes);
            totals.usagePercent = std::max(totals.usagePercent, percent);
        }
        for (const auto count : bucket.dropped)
        {
            totals.dropped += count;
        }
        for (const auto count : bucket.failed)
        {
            totals.dropped += count;
        }
        for (const auto count : bucket.rejected)
        {
            totals.dropped += count;
        }
    }
    // I218: the global budget drops too (`GlobalFull`) when it binds (2 x quota > global, e.g. a quota of 0), so the
    // sum against the capacity also counts. When the global quota does not bind it never exceeds the fullest bucket.
    if (m_queueCapacityBytes != 0)
    {
        const auto percent = static_cast<double>(charge) * 100.0 / static_cast<double>(m_queueCapacityBytes);
        totals.usagePercent = std::max(totals.usagePercent, percent);
    }
    m_totals = totals;
    m_totalsAt = now;
    m_hasTotals = true;
    return m_totals;
}

uint64_t WIndexerConnector::getQueueSize()
{
    if (m_closed.load(std::memory_order_acquire))
    {
        return 0;
    }
    return totals().retainedBytes;
}

double WIndexerConnector::getQueueUsagePercent()
{
    if (m_closed.load(std::memory_order_acquire) || m_queueCapacityBytes == 0)
    {
        return 0.0;
    }
    return std::min(totals().usagePercent, 100.0);
}

uint64_t WIndexerConnector::getDroppedEvents()
{
    return totals().dropped + m_discardedAfterShutdown.load(std::memory_order_relaxed);
}

json::Json WIndexerConnector::getEngineRemoteConfig()
{
    std::shared_ptr<indexer_client::IClient> reader;
    {
        std::lock_guard lock(m_mutex);
        reader = m_client;
    }
    if (!reader)
    {
        throw std::runtime_error("The indexer connector is shut down");
    }
    return remoteConfigFromClient(*reader, m_requestTimeout);
}

}; // namespace wiconnector
