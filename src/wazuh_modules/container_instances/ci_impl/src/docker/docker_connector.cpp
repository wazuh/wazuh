#include "docker_connector.hpp"

#include <algorithm>
#include <unordered_map>
#include <utility>
#include <vector>

namespace wazuh::container_instances
{

    namespace
    {

        constexpr auto RECONCILE_DEBOUNCE = std::chrono::milliseconds {500};
        constexpr auto BACKOFF_BASE = std::chrono::seconds {5};
        constexpr auto BACKOFF_CAP = std::chrono::seconds {60};
        constexpr std::size_t EVENT_DEDUPE_LIMIT = 1024;

    } // namespace

    DockerConnector::DockerConnector(IDockerApiClient& client,
                                     const ICgroupResolver& resolver,
                                     IMetadataStore& store,
                                     Logger logger)
        : m_client(client)
        , m_resolver(resolver)
        , m_store(store)
        , m_logger(std::move(logger))
    {
    }

    void DockerConnector::reSeed()
    {
        const auto summaries = m_client.listContainers();

        std::vector<ContainerRecord> records;
        records.reserve(summaries.size());
        for (const auto& summary : summaries)
        {
            try
            {
                records.push_back(m_client.inspect(summary.id).record);
            }
            catch (const DockerApiError& error)
            {
                if (error.httpStatus() == 404)
                {
                    m_logger(LogLevel::debug, "Container " + summary.id + " vanished before inspect");
                    continue; // Next reconcile removes it.
                }
                throw;
            }
        }

        const auto scan = m_resolver.scan();
        std::unordered_map<std::string, std::uint64_t> inodeByContainerId;
        for (const auto& entry : scan.containers)
        {
            inodeByContainerId.emplace(entry.containerId, entry.inode);
        }
        for (auto& record : records)
        {
            const auto it = inodeByContainerId.find(record.containerId);
            record.cgroupId = (it != inodeByContainerId.end()) ? it->second : 0;
        }

        m_store.applySnapshot(std::move(records), scan.allInodes, std::chrono::steady_clock::now());
        m_lastReconcile = std::chrono::steady_clock::now();
        m_reconcilePending = false;
    }

    void DockerConnector::handleEvent(const DockerEvent& event)
    {
        {
            std::lock_guard<std::mutex> lock(m_eventDedupeMutex);
            const auto key = std::make_tuple(event.containerId, event.action, event.timeNano);
            if (!m_seenEvents.insert(key).second)
            {
                return; // Duplicate from the since= resume overlap.
            }
            if (m_seenEvents.size() > EVENT_DEDUPE_LIMIT)
            {
                m_seenEvents.erase(m_seenEvents.begin());
            }
        }

        // Coalesce: churn-heavy hosts get at most one full reconcile per debounce
        // window. A suppressed reconcile is recovered by the next event or by the
        // full re-seed on stream reconnect; a quiet, healthy stream can defer it
        // indefinitely, which only delays removal of already-dead records.
        m_reconcilePending = true;
        if (std::chrono::steady_clock::now() - m_lastReconcile >= RECONCILE_DEBOUNCE)
        {
            reSeed();
        }
    }

    void DockerConnector::run(const StopController& stop)
    {
        auto backoff = BACKOFF_BASE;

        while (!stop.isStopRequested())
        {
            try
            {
                static_cast<void>(m_client.negotiateVersion());

                while (!stop.isStopRequested())
                {
                    // Capture since= BEFORE seeding so the seed window is covered
                    // by the stream; the (id, action, timeNano) dedupe absorbs the
                    // overlap. Re-seeding on every (re)connect also compensates
                    // for events since= cannot replay across daemon restarts.
                    const auto sinceSeconds = std::chrono::duration_cast<std::chrono::seconds>(
                                                  std::chrono::system_clock::now().time_since_epoch())
                                                  .count();
                    reSeed();
                    backoff = BACKOFF_BASE;

                    const auto outcome = m_client.streamEvents(
                        sinceSeconds, [this](const DockerEvent& event) { handleEvent(event); }, stop);

                    if (outcome.kind == StreamOutcome::Kind::cancelled)
                    {
                        return;
                    }

                    m_logger(LogLevel::warn, "Docker event stream disconnected: " + outcome.message);
                    if (!stop.waitFor(BACKOFF_BASE))
                    {
                        return;
                    }
                }
            }
            catch (const DockerVersionTooOld& error)
            {
                m_logger(LogLevel::error, std::string {error.what()} + " — container_instances inactive");
                while (!stop.isStopRequested())
                {
                    static_cast<void>(stop.waitFor(BACKOFF_CAP)); // Idle disabled for this run; no crash.
                }
                return;
            }
            catch (const std::exception& error)
            {
                m_logger(LogLevel::warn, std::string {"Docker connector error: "} + error.what());
                if (!stop.waitFor(backoff))
                {
                    return;
                }
                backoff = std::min(backoff * 2, std::chrono::seconds {BACKOFF_CAP});
            }
        }
    }

    RefreshOutcome DockerConnector::refreshOne(const std::string& containerId, std::uint64_t cgroupInode)
    {
        try
        {
            auto detail = m_client.inspect(containerId);
            detail.record.cgroupId = cgroupInode;
            m_store.upsertResolved(std::move(detail.record));
            return RefreshOutcome::resolved;
        }
        catch (const DockerApiError& error)
        {
            if (error.httpStatus() == 404)
            {
                return RefreshOutcome::notFound;
            }
            m_logger(LogLevel::debug, std::string {"On-demand inspect failed: "} + error.what());
            return RefreshOutcome::error;
        }
        catch (const std::exception& error)
        {
            m_logger(LogLevel::debug, std::string {"On-demand inspect failed: "} + error.what());
            return RefreshOutcome::error;
        }
    }

} // namespace wazuh::container_instances
