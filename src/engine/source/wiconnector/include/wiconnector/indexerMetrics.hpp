// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _WICONNECTOR_INDEXER_METRICS_HPP
#define _WICONNECTOR_INDEXER_METRICS_HPP

#include <memory>
#include <optional>

#include <fastmetrics/iManager.hpp>
#include <indexer_client/runtime.hpp>
#include <wiconnector/windexerconnector.hpp>

namespace wiconnector
{

/**
 * @brief Publishes the engine's indexer metrics on @p manager, as pull metrics registered once.
 *
 * - `indexer.queue.size`, `indexer.queue.usage.percent`, `indexer.events.dropped` and `indexer.events.deduplicated`:
 *   the connector's four getters.
 * - `indexer_client.bucket.analysisd.{events,raw}.<field>`: the library's catalog of each bucket (accepted, rejected,
 *   dropped, failed and retries by cause, retained/charge/quota bytes, bulk requests and bytes, latency histogram),
 *   from the same cached snapshot the four getters read (WIndexerConnector::getBucketMetric()). After the
 *   connector's shutdown() they keep the last snapshot; once the connector is gone they read 0.
 * - With @p runtime: `indexer_client.{runtime,query,pit}.<field>` and `indexer_client.node.<i>.<field>` from
 *   RuntimeRef::snapshot(), through an indexer_client::MetricsSlot refreshed at most once per
 *   WIndexerConnector::METRICS_TTL. The node family is sized by the snapshot taken here (fixed for the life of the
 *   runtime). Counters are published as integers, gauges as doubles.
 *
 * The connector is held weakly. Names already registered are left as they are (fastmetrics keeps the first).
 */
void registerIndexerMetrics(fastmetrics::IManager& manager,
                            const std::weak_ptr<WIndexerConnector>& connector,
                            const std::optional<indexer_client::RuntimeRef>& runtime);

} // namespace wiconnector

#endif // _WICONNECTOR_INDEXER_METRICS_HPP
