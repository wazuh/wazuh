#include <array>
#include <mutex>
#include <regex>
#include <set>
#include <stdexcept>
#include <utility>

#include <fmt/format.h>

#include <base/error.hpp>
#include <base/logging.hpp>
#include <base/utils/generator.hpp>

#include <cmcontent/rulesetSink.hpp>

namespace cmcontent
{

namespace
{

constexpr std::string_view LOG_MODULE_NAME {"CM::Sync"};

/// What kind of resource an index holds.
enum class ResourceKind
{
    Kvdb,
    Decoder,
    Filter,
    Integration,
    Policy,
    Unknown
};

/**
 * @brief Classify a hit by the index it came from.
 *
 * Substring matching rather than exact names: the PIT is opened over aliases with wildcard
 * expansion, so `_index` reports whatever concrete backing index the alias resolves to, and that
 * name carries a version or date suffix.
 *
 * @param indexName The hit's `_index`.
 * @return The resource kind, or Unknown when the name matches nothing.
 */
ResourceKind kindFromIndexName(const std::string& indexName)
{
    static const std::array<std::pair<std::regex, ResourceKind>, 5> patterns {
        {{std::regex(R"(.*kvdbs.*)"), ResourceKind::Kvdb},
         {std::regex(R"(.*decoders.*)"), ResourceKind::Decoder},
         {std::regex(R"(.*filters.*)"), ResourceKind::Filter},
         {std::regex(R"(.*integrations.*)"), ResourceKind::Integration},
         {std::regex(R"(.*policies.*)"), ResourceKind::Policy}}};

    for (const auto& [pattern, kind] : patterns)
    {
        if (std::regex_match(indexName, pattern))
        {
            return kind;
        }
    }

    return ResourceKind::Unknown;
}

cm::store::NamespaceId generateNamespaceId(std::string_view space)
{
    return cm::store::NamespaceId {fmt::format("cmsync_{}_{}", space, base::utils::generators::randomHexString(4))};
}

} // namespace

RulesetSpaceSink::RulesetSpaceSink(std::weak_ptr<cm::crud::ICrudService> crud,
                                   std::weak_ptr<router::IRouterAPI> router,
                                   std::string space,
                                   std::string routeName)
    : m_crud(std::move(crud))
    , m_router(std::move(router))
    , m_space(std::move(space))
    , m_routeName(std::move(routeName))
{
}

RulesetSpaceSink::~RulesetSpaceSink()
{
    std::lock_guard<std::mutex> lock {m_mutex};
    discardStaging();
}

void RulesetSpaceSink::prepare(const std::optional<cm::store::NamespaceId>& currentNamespaceId)
{
    std::lock_guard<std::mutex> lock {m_mutex};
    m_currentNamespaceId = currentNamespaceId;
}

RulesetOutcome RulesetSpaceSink::takeOutcome()
{
    std::lock_guard<std::mutex> lock {m_mutex};
    return std::exchange(m_outcome, RulesetOutcome {});
}

content_manager::SessionDecision RulesetSpaceSink::beginSession(const content_manager::SessionInfo& info) noexcept
{
    using namespace content_manager;

    std::lock_guard<std::mutex> lock {m_mutex};

    m_outcome = RulesetOutcome {};
    m_remoteHash = info.remoteToken;

    auto router = m_router.lock();
    auto crud = m_crud.lock();
    if (!router || !crud)
    {
        return SessionDecision::Abort;
    }

    try
    {
        const bool routeExists = router->existsEntry(m_routeName);

        // A policy is only usable if it is enabled AND actually carries integrations. The two are
        // separate fields in the indexer and can disagree; treating an integration-less policy as
        // enabled would deploy a namespace that routes nothing.
        const bool enabledFlag = info.probeMetadata.value("enabled", true);
        const bool hasIntegrations = info.probeMetadata.contains("integrations")
                                         ? !info.probeMetadata.at("integrations").empty()
                                         : true;

        if (!enabledFlag || !hasIntegrations)
        {
            teardown();
            m_outcome.disabled = true;
            m_outcome.routeAvailable = false;
            return SessionDecision::Skip;
        }

        if (info.kind == SessionKind::NoChange)
        {
            // The remote hash matches what was committed, but that only says the *content* has not
            // moved. If the route was deleted out of band there is nothing serving it, and the
            // caller asks for a forced reload in that case rather than this sink second-guessing
            // the plan — a NoChange session carries no documents to deploy.
            m_outcome.routeAvailable = routeExists;
            m_outcome.hash = info.remoteToken;
            return SessionDecision::Skip;
        }

        discardStaging();
        m_accumulator = Accumulator {};

        auto candidate = generateNamespaceId(m_space);
        while (crud->existsNamespace(candidate))
        {
            candidate = generateNamespaceId(m_space);
        }
        m_stagingNamespaceId = candidate;

        LOG_DEBUG("[{}] Staging namespace '{}' allocated for space '{}'",
                  LOG_MODULE_NAME,
                  m_stagingNamespaceId->toStr(),
                  m_space);
        return SessionDecision::Proceed;
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("[{}] Could not start the sync of space '{}': {}", LOG_MODULE_NAME, m_space, e.what());
        return SessionDecision::Abort;
    }
    catch (...)
    {
        return SessionDecision::Abort;
    }
}

content_manager::PageAck RulesetSpaceSink::acceptPage(const content_manager::ContentPage& page) noexcept
{
    using namespace content_manager;

    if (page.hits == nullptr)
    {
        return PageAck {PageStatus::Accepted, {}};
    }

    std::lock_guard<std::mutex> lock {m_mutex};

    try
    {
        for (const auto& hit : *page.hits)
        {
            if (!hit.contains("_source") || !hit.at("_source").is_object())
            {
                LOG_WARNING("[{}] Hit without _source for space '{}', skipping", LOG_MODULE_NAME, m_space);
                continue;
            }

            const auto& source = hit.at("_source");
            if (!source.contains("document"))
            {
                LOG_WARNING("[{}] Hit without a document for space '{}', skipping", LOG_MODULE_NAME, m_space);
                continue;
            }

            const auto indexName = hit.value("_index", std::string {});
            const auto kind = kindFromIndexName(indexName);
            if (kind == ResourceKind::Unknown)
            {
                return PageAck {PageStatus::Reject,
                                "cannot determine the resource type from index name: " + indexName};
            }

            json::Json document {source.at("document").dump().c_str()};

            switch (kind)
            {
                case ResourceKind::Kvdb: m_accumulator.kvdbs.emplace_back(std::move(document)); break;
                case ResourceKind::Decoder: m_accumulator.decoders.emplace_back(std::move(document)); break;
                case ResourceKind::Filter: m_accumulator.filters.emplace_back(std::move(document)); break;
                case ResourceKind::Integration: m_accumulator.integrations.emplace_back(std::move(document)); break;

                case ResourceKind::Policy:
                {
                    // The hash is carried beside the document, not inside it, and the namespace
                    // import expects to find it at /hash.
                    if (!source.contains("space") || !source.at("space").contains("hash") ||
                        !source.at("space").at("hash").contains("sha256") ||
                        !source.at("space").at("hash").at("sha256").is_string())
                    {
                        return PageAck {PageStatus::Reject, "space.hash.sha256 field not found for policy"};
                    }

                    document.setString(source.at("space").at("hash").at("sha256").get<std::string>(), "/hash");
                    document.setString(m_space, "/origin_space");
                    m_accumulator.policy = std::move(document);
                    m_accumulator.policySeen = true;
                    break;
                }

                default: break;
            }
        }

        // Always Accepted: none of this exists outside memory until commit() imports it, so there
        // is no intermediate state a crash could resume from.
        return PageAck {PageStatus::Accepted, {}};
    }
    catch (const std::exception& e)
    {
        return PageAck {PageStatus::Reject, e.what()};
    }
    catch (...)
    {
        return PageAck {PageStatus::Reject, "unknown error while assembling the ruleset"};
    }
}

content_manager::CommitResult RulesetSpaceSink::commit(const content_manager::CommitInfo&) noexcept
{
    using namespace content_manager;

    std::lock_guard<std::mutex> lock {m_mutex};

    if (!m_stagingNamespaceId.has_value())
    {
        return CommitResult {CommitStatus::RejectedRetrySame, "no staging namespace to promote"};
    }

    auto crud = m_crud.lock();
    if (!crud)
    {
        return CommitResult {CommitStatus::RejectedRetrySame, "the namespace store is gone"};
    }

    if (!m_accumulator.policySeen)
    {
        // Without a policy there is nothing to route. Treated as a content problem rather than a
        // transient one so the next cycle re-fetches from scratch instead of trusting the token.
        discardStaging();
        return CommitResult {CommitStatus::RejectedRetryFull, "no policy document was delivered for this space"};
    }

    const auto staging = *m_stagingNamespaceId;

    try
    {
        crud->importNamespace(staging,
                              m_accumulator.kvdbs,
                              m_accumulator.decoders,
                              m_accumulator.filters,
                              m_accumulator.integrations,
                              m_accumulator.policy,
                              /*softValidation=*/true);
    }
    catch (const std::exception& e)
    {
        discardStaging();
        LOG_WARNING("[{}] Failed to import the namespace for space '{}': {}", LOG_MODULE_NAME, m_space, e.what());
        return CommitResult {CommitStatus::RejectedRetrySame, e.what()};
    }

    try
    {
        routeTo(staging);
    }
    catch (const std::exception& e)
    {
        // The namespace was imported but nothing points at it, so it is garbage; removing it here
        // is what keeps the store from accumulating one dead namespace per failed cycle.
        discardStaging();
        LOG_ERROR("[{}] Failed to sync the namespace in route for space '{}': {}", LOG_MODULE_NAME, m_space, e.what());
        return CommitResult {CommitStatus::RejectedRetrySame, e.what()};
    }

    // The swap succeeded: the staging namespace is now the live one, so it must not be discarded.
    m_stagingNamespaceId.reset();

    if (m_currentNamespaceId.has_value() && *m_currentNamespaceId != staging)
    {
        try
        {
            crud->deleteNamespace(*m_currentNamespaceId);
        }
        catch (const std::exception& e)
        {
            // Not a commit failure: the new content is already live. A leaked namespace costs disk,
            // a rolled-back promotion costs correctness.
            LOG_WARNING("[{}] Failed to delete the previous namespace '{}' for space '{}': {}",
                        LOG_MODULE_NAME,
                        m_currentNamespaceId->toStr(),
                        m_space,
                        e.what());
        }
    }

    m_currentNamespaceId = staging;
    m_outcome.applied = true;
    m_outcome.newNamespaceId = staging;
    m_outcome.hash = m_remoteHash;
    m_outcome.routeAvailable = true;

    LOG_INFO("[{}] Successfully synchronized space '{}'", LOG_MODULE_NAME, m_space);
    return CommitResult {CommitStatus::Committed, {}};
}

void RulesetSpaceSink::abort(content_manager::AbortReason, const std::string& detail) noexcept
{
    std::lock_guard<std::mutex> lock {m_mutex};

    if (m_stagingNamespaceId.has_value())
    {
        LOG_DEBUG("[{}] Discarding the staging namespace for space '{}': {}", LOG_MODULE_NAME, m_space, detail);
    }
    discardStaging();
}

void RulesetSpaceSink::teardown() noexcept
{
    auto router = m_router.lock();
    auto crud = m_crud.lock();
    if (!router || !crud)
    {
        return;
    }

    try
    {
        if (!router->existsEntry(m_routeName))
        {
            LOG_DEBUG("[{}] Policy for space '{}' is disabled in the indexer and no route exists, skipping",
                      LOG_MODULE_NAME,
                      m_space);
            return;
        }

        LOG_INFO("[{}] Policy for space '{}' is disabled in the indexer, removing route and namespace",
                 LOG_MODULE_NAME,
                 m_space);

        if (auto error = router->deleteEntry(m_routeName); base::isError(error))
        {
            LOG_WARNING("[{}] Failed to delete route '{}' for space '{}': {}",
                        LOG_MODULE_NAME,
                        m_routeName,
                        m_space,
                        base::getError(error).message);
        }

        if (m_currentNamespaceId.has_value())
        {
            crud->deleteNamespace(*m_currentNamespaceId);
            m_currentNamespaceId.reset();
        }
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("[{}] Failed to tear down space '{}': {}", LOG_MODULE_NAME, m_space, e.what());
    }
    catch (...)
    {
        LOG_WARNING("[{}] Failed to tear down space '{}'", LOG_MODULE_NAME, m_space);
    }
}

void RulesetSpaceSink::routeTo(const cm::store::NamespaceId& namespaceId)
{
    auto router = m_router.lock();
    if (!router)
    {
        throw std::runtime_error("the router is gone");
    }

    if (router->existsEntry(m_routeName))
    {
        if (auto error = router->hotSwapNamespace(m_routeName, namespaceId); base::isError(error))
        {
            throw std::runtime_error(
                fmt::format("Failed to hot-swap namespace in route '{}': {}", m_routeName, base::getError(error).message));
        }
        return;
    }

    // TODO: remove router priority and evaluate route lexicographical order instead.
    std::set<std::size_t> usedPriorities;
    for (const auto& entry : router->getEntries())
    {
        usedPriorities.insert(entry.priority());
    }

    std::size_t priority = 0;
    for (std::size_t candidate = 1; candidate <= router::prod::EntryPost::maxPriority(); ++candidate)
    {
        if (usedPriorities.find(candidate) == usedPriorities.end())
        {
            priority = candidate;
            break;
        }
    }
    if (priority == 0)
    {
        throw std::runtime_error("No available priority for new route");
    }

    router::prod::EntryPost newEntry {m_routeName, namespaceId, priority};
    if (auto error = router->postEntry(newEntry); base::isError(error))
    {
        throw std::runtime_error(
            fmt::format("Failed to create new route '{}': {}", m_routeName, base::getError(error).message));
    }
}

void RulesetSpaceSink::discardStaging() noexcept
{
    if (!m_stagingNamespaceId.has_value())
    {
        return;
    }

    const auto staging = *m_stagingNamespaceId;
    m_stagingNamespaceId.reset();

    auto crud = m_crud.lock();
    if (!crud)
    {
        return;
    }

    try
    {
        if (crud->existsNamespace(staging))
        {
            crud->deleteNamespace(staging);
        }
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("[{}] Failed to roll back the staging namespace '{}': {}", LOG_MODULE_NAME, staging.toStr(), e.what());
    }
    catch (...)
    {
        LOG_WARNING("[{}] Failed to roll back the staging namespace '{}'", LOG_MODULE_NAME, staging.toStr());
    }
}

} // namespace cmcontent
