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

        /// How often a reconcile runs with NOTHING pending.
        ///
        /// The debounce's trailing edge only runs while work is outstanding, and
        /// reSeed() clears that flag — so on a host that goes quiet the connector
        /// stops reconciling entirely. That would merely be idle, except that
        /// applySnapshot() is the only place removal grace, pending TTL and
        /// verdict liveness are evaluated, and the connectors are its only
        /// callers. A quiet host therefore stops expiring anything: containers
        /// removed with a live key keep their grace timestamp and are never
        /// erased, which is why `docker rm` on an idle host left records in the
        /// list indefinitely until some unrelated event happened along.
        ///
        /// Well under REMOVAL_GRACE (60 s) so expiry is evaluated several times
        /// inside the window, and far above the 500 ms poll so a quiet host pays
        /// one snapshot every ten seconds rather than two a second. The default
        /// lives on the constructor; tests inject a shorter one.
        constexpr auto BACKOFF_BASE = std::chrono::seconds {5};
        constexpr auto BACKOFF_CAP = std::chrono::seconds {60};
        constexpr std::size_t EVENT_DEDUPE_LIMIT = 1024;

    } // namespace

    DockerConnector::DockerConnector(IDockerApiClient& client,
                                     const ICgroupResolver& resolver,
                                     IMetadataStore& store,
                                     SourceId source,
                                     Logger logger,
                                     std::chrono::milliseconds idleReconcileInterval)
        : m_client(client)
        , m_resolver(resolver)
        , m_store(store)
        , m_source(std::move(source))
        , m_logger(std::move(logger))
        , m_idleReconcileInterval(idleReconcileInterval)
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
            // The host's key, not simply the cgroup inode: on a legacy hierarchy the
            // cgroup inode is a number no event ever carries, so keying on it answers
            // every correlation lookup with a miss while looking entirely healthy.
            inodeByContainerId.emplace(entry.containerId, hostKeyOf(entry, scan.keyKind));
        }
        for (auto& record : records)
        {
            const auto it = inodeByContainerId.find(record.containerId);
            record.hostKey = (it != inodeByContainerId.end()) ? it->second : 0;
        }

        m_store.applySnapshot(m_source, std::move(records), scan.allHostKeys, std::chrono::steady_clock::now());
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
        // window. What the window defers, flushPendingReconcile() picks up one
        // window later.
        m_reconcilePending = true;
        flushPendingReconcile();
    }

    /// Runs a deferred reconcile once the debounce window has passed.
    ///
    /// This is the trailing edge of the debounce, and without it the leading edge
    /// alone LOSES WORK rather than merely delaying it. `handleEvent` re-seeds
    /// only when the window has elapsed; a start event arriving inside the window
    /// is dropped, and since a re-seed is a full snapshot taken at a point in
    /// time, a container that began after the previous snapshot is in neither.
    /// It then stays absent from the store — not stale, absent — until some
    /// unrelated event or a stream reconnect happens to trigger another snapshot.
    /// On a host that goes quiet right after a burst, that is indefinite.
    ///
    /// Consumers cannot paper over it: they read the store, so neither a faster
    /// poll nor a change notification can surface a container the store never
    /// recorded. Grace-expiry sweeps live inside applySnapshot() too, so the same
    /// gap strands removed records.
    ///
    /// Called from two places: every event (leading edge) and the stream's idle
    /// tick (trailing edge). Both run on the connector's own thread, which is why
    /// m_reconcilePending and m_lastReconcile need no synchronisation.
    void DockerConnector::flushPendingReconcile()
    {
        const auto now = std::chrono::steady_clock::now();

        if (m_reconcilePending && now - m_lastReconcile >= RECONCILE_DEBOUNCE)
        {
            reSeed();
            return;
        }

        // Nothing pending, but the store still needs a snapshot periodically:
        // everything that expires — removal grace, pending TTL, verdict liveness
        // — is evaluated inside applySnapshot() and nowhere else. Kubernetes gets
        // this for free because the apiserver closes its watch every few minutes
        // and the re-list reconciles unconditionally; Docker's event stream is
        // deliberately unterminated, so a quiet host never reconciles again.
        if (now - m_lastReconcile >= m_idleReconcileInterval)
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
                        sinceSeconds,
                        [this](const DockerEvent& event) { handleEvent(event); },
                        stop,
                        [this] { flushPendingReconcile(); });

                    if (outcome.kind == StreamOutcome::Kind::cancelled)
                    {
                        return;
                    }

                    // Mirrors the Kubernetes connector's post-watch flush: a
                    // disconnect is itself a quiet period, and the re-seed below
                    // happens only after a backoff wait.
                    flushPendingReconcile();

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
            detail.record.hostKey = cgroupInode;
            m_store.upsertResolved(m_source, std::move(detail.record));
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
