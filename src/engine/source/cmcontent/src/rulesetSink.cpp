// SPDX-License-Identifier: AGPL-3.0-or-later
#include <array>
#include <set>
#include <stdexcept>
#include <string_view>
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
ResourceKind kindFromIndexName(std::string_view indexName)
{
    // Substring search instead of std::regex: libstdc++'s regex recurses per character, so an unbounded name
    // overflows the stack.
    static constexpr std::array<std::pair<std::string_view, ResourceKind>, 5> patterns {
        {{"kvdbs", ResourceKind::Kvdb},
         {"decoders", ResourceKind::Decoder},
         {"filters", ResourceKind::Filter},
         {"integrations", ResourceKind::Integration},
         {"policies", ResourceKind::Policy}}};

    for (const auto& [pattern, kind] : patterns)
    {
        if (indexName.find(pattern) != std::string_view::npos)
        {
            return kind;
        }
    }

    return ResourceKind::Unknown;
}

/// Every namespace a space's sink creates starts with this, which is how orphans are found.
std::string namespacePrefix(std::string_view space)
{
    return fmt::format("cmsync_{}_", space);
}

cm::store::NamespaceId generateNamespaceId(std::string_view space)
{
    return cm::store::NamespaceId {namespacePrefix(space) + base::utils::generators::randomHexString(4)};
}

} // namespace

RulesetSpaceSink::RulesetSpaceSink(std::weak_ptr<cm::crud::ICrudService> crud,
                                   std::weak_ptr<router::IRouterAPI> router,
                                   std::string space)
    : m_crud(std::move(crud))
    , m_router(std::move(router))
    , m_space(std::move(space))
    , m_routeName(routeName(m_space))
{
}

RulesetSpaceSink::~RulesetSpaceSink()
{
    discardStaging();
}

std::string RulesetSpaceSink::routeName(std::string_view space)
{
    return fmt::format("cmsync_{}", space);
}

RulesetDeployment RulesetSpaceSink::deployment() const noexcept
{
    RulesetDeployment deployment;
    deployment.enabled = m_policyEnabled;

    try
    {
        auto router = m_router.lock();
        if (!router || !router->existsEntry(m_routeName))
        {
            return deployment;
        }

        const auto entry = router->getEntry(m_routeName);
        if (!base::isError(entry))
        {
            deployment.available = true;
            deployment.hash = base::getResponse(entry).hash();
        }
    }
    catch (...)
    {
        // Reported as not available: the status must never take the sync down with it.
    }
    return deployment;
}

void RulesetSpaceSink::collectOrphanNamespaces() noexcept
{
    auto crud = m_crud.lock();
    auto router = m_router.lock();
    if (!crud || !router)
    {
        return;
    }

    try
    {
        std::optional<cm::store::NamespaceId> served;
        if (router->existsEntry(m_routeName))
        {
            const auto entry = router->getEntry(m_routeName);
            if (base::isError(entry))
            {
                LOG_WARNING("[{}] Skipping orphan collection for space '{}': its route could not be read",
                            LOG_MODULE_NAME,
                            m_space);
                return;
            }
            served = base::getResponse(entry).namespaceId();
        }

        const auto prefix = namespacePrefix(m_space);
        for (const auto& candidate : crud->listNamespaces())
        {
            if (candidate.toStr().rfind(prefix, 0) != 0 || (served.has_value() && candidate == *served))
            {
                continue;
            }
            LOG_INFO("[{}] Removing the orphaned namespace '{}' left by an interrupted sync",
                     LOG_MODULE_NAME,
                     candidate.toStr());
            crud->deleteNamespace(candidate);
        }
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("[{}] Could not collect orphaned namespaces of space '{}': {}", LOG_MODULE_NAME, m_space, e.what());
    }
}

content_manager::SessionDecision RulesetSpaceSink::beginSession(const content_manager::SessionInfo& info) noexcept
{
    using namespace content_manager;

    auto crud = m_crud.lock();
    if (!crud || m_router.expired())
    {
        return SessionDecision::Abort;
    }

    // No policy document for the space at all: nothing to deploy, and nothing to tear down either.
    if (info.kind == SessionKind::NoChange && info.remoteToken.empty())
    {
        LOG_DEBUG("[{}] Space '{}' has no policy in the indexer", LOG_MODULE_NAME, m_space);
        return SessionDecision::Skip;
    }

    // A policy is usable only if it is enabled AND carries integrations. Either field missing or
    // ill-typed is a malformed document: the cycle aborts and the deployed ruleset stays in force,
    // rather than one bad document stopping event processing for the space.
    const auto& metadata = info.probeMetadata;
    const auto enabled = metadata.find("enabled");
    const auto integrations = metadata.find("integrations");
    if (enabled == metadata.end() || !enabled->is_boolean() || integrations == metadata.end()
        || !integrations->is_array())
    {
        LOG_WARNING("[{}] The policy of space '{}' has no boolean 'enabled' or no 'integrations' array; keeping the "
                    "deployed ruleset",
                    LOG_MODULE_NAME,
                    m_space);
        return SessionDecision::Abort;
    }

    m_policyEnabled = enabled->get<bool>() && !integrations->empty();
    if (!*m_policyEnabled)
    {
        teardown();
        return SessionDecision::Skip;
    }

    if (info.kind == SessionKind::NoChange)
    {
        return SessionDecision::Skip;
    }

    try
    {
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
                return PageAck {PageStatus::Reject, "cannot determine the resource type from index name: " + indexName};
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
                    if (!source.contains("space") || !source.at("space").contains("hash")
                        || !source.at("space").at("hash").contains("sha256")
                        || !source.at("space").at("hash").at("sha256").is_string())
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
    const auto previous = servedNamespace();

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

    if (previous.has_value() && *previous != staging)
    {
        try
        {
            crud->deleteNamespace(*previous);
        }
        catch (const std::exception& e)
        {
            // Not a commit failure: the new content is already live. A leaked namespace costs disk
            // (and is collected at the next start), a rolled-back promotion costs correctness.
            LOG_WARNING("[{}] Failed to delete the previous namespace '{}' for space '{}': {}",
                        LOG_MODULE_NAME,
                        previous->toStr(),
                        m_space,
                        e.what());
        }
    }

    LOG_INFO("[{}] Successfully synchronized space '{}'", LOG_MODULE_NAME, m_space);
    return CommitResult {CommitStatus::Committed, {}};
}

void RulesetSpaceSink::abort(content_manager::AbortReason, const std::string& detail) noexcept
{
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

        const auto served = servedNamespace();
        if (auto error = router->deleteEntry(m_routeName); base::isError(error))
        {
            LOG_WARNING("[{}] Failed to delete route '{}' for space '{}': {}",
                        LOG_MODULE_NAME,
                        m_routeName,
                        m_space,
                        base::getError(error).message);
            return;
        }

        if (served.has_value())
        {
            crud->deleteNamespace(*served);
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

std::string RulesetSpaceSink::load(std::string_view) noexcept
{
    try
    {
        auto router = m_router.lock();
        if (!router || !router->existsEntry(m_routeName))
        {
            return {};
        }

        const auto entry = router->getEntry(m_routeName);
        if (base::isError(entry))
        {
            return {};
        }

        // A disabled route is not serving the content it was built from, so it must not count as
        // "already at this hash".
        const auto& served = base::getResponse(entry);
        return served.status() == ::router::env::State::ENABLED ? served.hash() : std::string {};
    }
    catch (...)
    {
        return {};
    }
}

bool RulesetSpaceSink::store(std::string_view, std::string_view) noexcept
{
    return true;
}

bool RulesetSpaceSink::clear(std::string_view) noexcept
{
    return true;
}

std::optional<cm::store::NamespaceId> RulesetSpaceSink::servedNamespace() const noexcept
{
    try
    {
        auto router = m_router.lock();
        if (!router || !router->existsEntry(m_routeName))
        {
            return std::nullopt;
        }

        const auto entry = router->getEntry(m_routeName);
        if (base::isError(entry))
        {
            return std::nullopt;
        }
        return base::getResponse(entry).namespaceId();
    }
    catch (...)
    {
        return std::nullopt;
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
            throw std::runtime_error(fmt::format(
                "Failed to hot-swap namespace in route '{}': {}", m_routeName, base::getError(error).message));
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
        LOG_WARNING(
            "[{}] Failed to roll back the staging namespace '{}': {}", LOG_MODULE_NAME, staging.toStr(), e.what());
    }
    catch (...)
    {
        LOG_WARNING("[{}] Failed to roll back the staging namespace '{}'", LOG_MODULE_NAME, staging.toStr());
    }
}

} // namespace cmcontent
