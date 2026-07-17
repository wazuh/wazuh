#include "query_service.hpp"

#include <thread>
#include <utility>

namespace wazuh::container_instances
{

    namespace
    {

        constexpr int PENDING_RETRY_AFTER_MS = 500;

        QueryResponse fromLookup(const LookupResult& lookup)
        {
            QueryResponse response;
            switch (lookup.status)
            {
                case LookupResult::Status::resolved:
                    response.status = QueryResponse::Status::resolved;
                    response.record = lookup.record;
                    break;
                case LookupResult::Status::verdict:
                    response.status = QueryResponse::Status::notContainer;
                    response.reason = lookup.reason;
                    break;
                case LookupResult::Status::pending:
                    response.status = QueryResponse::Status::pending;
                    response.retryAfterMs = PENDING_RETRY_AFTER_MS;
                    break;
                case LookupResult::Status::miss:
                    response.status = QueryResponse::Status::error;
                    response.errorCode = QueryResponse::ErrorCode::internal;
                    break;
            }
            return response;
        }

    } // namespace

    QueryService::QueryService(IMetadataStore& store,
                               std::vector<RefresherBinding> refreshers,
                               const ICgroupResolver& resolver,
                               RetryPolicy coldCacheRetry,
                               std::string connectorName,
                               Logger logger,
                               Sleeper sleeper)
        : m_store(store)
        , m_refreshers(std::move(refreshers))
        , m_resolver(resolver)
        , m_coldCacheRetry(coldCacheRetry)
        , m_connectorName(std::move(connectorName))
        , m_logger(std::move(logger))
        , m_sleeper(sleeper ? std::move(sleeper) : [](std::chrono::milliseconds delay)
                        { std::this_thread::sleep_for(delay); })
    {
    }

    QueryResponse QueryService::handle(const QueryRequest& request)
    {
        try
        {
            if (request.op == QueryRequest::Op::list)
            {
                QueryResponse response;
                response.status = QueryResponse::Status::ok;
                response.containers = m_store.listContainers();
                response.connectorName = m_connectorName;
                return response;
            }
            if (request.op == QueryRequest::Op::status)
            {
                QueryResponse response;
                response.status = QueryResponse::Status::ok;
                response.stats = m_store.stats();
                response.connectorName = m_connectorName;
                return response;
            }
            return resolve(request);
        }
        catch (const std::exception& error)
        {
            m_logger(LogLevel::warn, std::string {"Query handling failed: "} + error.what());
            QueryResponse response;
            response.status = QueryResponse::Status::error;
            response.errorCode = QueryResponse::ErrorCode::internal;
            response.errorMessage = "internal error";
            return response;
        }
    }

    QueryResponse QueryService::resolve(const QueryRequest& request)
    {
        const auto byCgroup = m_store.lookupByCgroup(request.cgroupId);
        if (byCgroup.status != LookupResult::Status::miss)
        {
            return fromLookup(byCgroup);
        }

        // Optional secondary keys (lifecycle/debug): cheap index hits before the
        // cold path.
        if (request.containerId)
        {
            const auto byId = m_store.lookupByContainerId(*request.containerId);
            if (byId.status == LookupResult::Status::resolved)
            {
                return fromLookup(byId);
            }
        }
        if (request.podUid && request.containerName)
        {
            const auto byPod = m_store.lookupByPodContainer(*request.podUid, *request.containerName);
            if (byPod.status == LookupResult::Status::resolved)
            {
                return fromLookup(byPod);
            }
        }

        return coldResolve(request.cgroupId);
    }

    QueryResponse QueryService::coldResolve(std::uint64_t cgroupInode)
    {
        for (int attempt = 1; attempt <= m_coldCacheRetry.maxAttempts; ++attempt)
        {
            const auto entry = m_resolver.scanOne(cgroupInode);

            if (entry && entry->containerId.empty())
            {
                // The cgroup exists but is no container: permanent host verdict,
                // never enters the retry loop again.
                m_store.upsertVerdict(cgroupInode, VerdictReason::hostProcess);
                QueryResponse response;
                response.status = QueryResponse::Status::notContainer;
                response.reason = VerdictReason::hostProcess;
                return response;
            }

            if (entry)
            {
                // Route by the resolver's hint; an unknown hint (bare-hex leaf)
                // tries every source.
                const bool dockerHinted = entry->hint == RuntimeHint::docker;
                const bool anyHint = entry->hint == RuntimeHint::unknown;
                for (const auto& binding : m_refreshers)
                {
                    if (!anyHint && binding.docker != dockerHinted)
                    {
                        continue;
                    }
                    const auto outcome = binding.refresher->refreshOne(entry->containerId, cgroupInode);
                    if (outcome == RefreshOutcome::resolved)
                    {
                        const auto lookup = m_store.lookupByCgroup(cgroupInode);
                        if (lookup.status != LookupResult::Status::miss)
                        {
                            return fromLookup(lookup);
                        }
                    }
                }
            }

            m_logger(LogLevel::warn,
                     "Cold-cache resolution of cgroup inode " + std::to_string(cgroupInode) + " failed (attempt " +
                         std::to_string(attempt) + "/" + std::to_string(m_coldCacheRetry.maxAttempts) + ")");
            if (attempt < m_coldCacheRetry.maxAttempts)
            {
                m_sleeper(m_coldCacheRetry.backoffFor(attempt));
            }
        }

        m_store.upsertPending(cgroupInode, m_coldCacheRetry.maxAttempts, std::chrono::steady_clock::now());
        QueryResponse response;
        response.status = QueryResponse::Status::pending;
        response.retryAfterMs = PENDING_RETRY_AFTER_MS;
        return response;
    }

} // namespace wazuh::container_instances
