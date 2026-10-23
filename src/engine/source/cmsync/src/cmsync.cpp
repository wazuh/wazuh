// SPDX-License-Identifier: AGPL-3.0-or-later
#include <algorithm>
#include <ctime>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include <fmt/format.h>

#include <base/error.hpp>
#include <base/json.hpp>
#include <base/logging.hpp>
#include <base/utils/metaHelpers.hpp>

#include <cmsync/cmsync.hpp>

namespace
{

const base::Name STORE_NAME_CMSYNC {"cmsync/status/0"};
const std::string COMPONENT_NAME {"CM::Sync"};

constexpr std::string_view JPATH_ORIGIN {"/origin_space"};
constexpr std::string_view JPATH_LAST_SUCCESSFUL_UPDATE {"/last_successful_update"};
constexpr std::string_view JPATH_ENABLED {"/enabled"};

/// The tracked spaces, and the CTI consumer that gates each (none for one no consumer writes).
const std::vector<std::pair<std::string, std::optional<std::string>>> TRACKED_SPACES {
    {"standard", std::string {cmcontent::RULESET_CONSUMER_ID}}, {"custom", std::nullopt}};

} // namespace

namespace cm::sync
{

CMSync::CMSync(const std::shared_ptr<cm::crud::ICrudService>& cmcrudPtr,
               const std::shared_ptr<::store::IStore>& storePtr,
               const std::shared_ptr<router::IRouterAPI>& routerPtr,
               const cmcontent::TopicFactory& topicFactory,
               const cmcontent::Options& contentOptions,
               cmcontent::RetryPolicy retry)
    : m_store(storePtr)
    , m_retry(retry)
{
    if (!topicFactory)
    {
        throw std::invalid_argument {"CMSync needs a topic factory"};
    }

    m_spaces.reserve(TRACKED_SPACES.size());
    for (const auto& [name, consumerId] : TRACKED_SPACES)
    {
        Space space;
        space.name = name;
        space.sink = std::make_shared<cmcontent::RulesetSpaceSink>(cmcrudPtr, routerPtr, name);
        space.sink->collectOrphanNamespaces();
        space.deployment = space.sink->deployment();
        // The sink is also the topic's token store: the deployed route's hash is the token.
        space.topic = topicFactory(cmcontent::rulesetTopic(name),
                                   cmcontent::rulesetSpec(name, contentOptions, consumerId),
                                   space.sink,
                                   space.sink);
        m_spaces.push_back(std::move(space));
    }

    loadState();
    publishStatus();
}

CMSync::~CMSync() = default;

bool CMSync::synchronize()
{
    std::lock_guard<std::mutex> lock {m_syncMutex};
    LOG_DEBUG("[{}] Checking for ruleset updates", COMPONENT_NAME);

    bool changed = false;
    for (auto& space : m_spaces)
    {
        if (m_shutdownRequested.load())
        {
            LOG_INFO("[{}] Synchronization aborted by shutdown", COMPONENT_NAME);
            break;
        }
        changed = syncSpace(space) || changed;
    }
    publishStatus();

    if (changed)
    {
        try
        {
            persistState();
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("[{}] Failed to persist the sync state: {}", COMPONENT_NAME, e.what());
        }
    }

    if (m_shutdownRequested.load())
    {
        return false;
    }
    // No route and no policy read as disabled: the indexer failed, or the content is not published or the
    // consumer not ready yet. All of these can clear before the next regular run. A space that keeps an older
    // route does not count: that route still processes events.
    return std::any_of(m_spaces.begin(),
                       m_spaces.end(),
                       [](const Space& space)
                       { return !space.deployment.available && !(space.policyKnown && !space.enabled); });
}

bool CMSync::syncSpace(Space& space)
{
    using content_manager::CycleStatus;

    const auto previous = space.status;
    space.status = base::SyncStatus::UPDATING;
    publishStatus();

    const auto outcome = cmcontent::runWithRetries(*space.topic,
                                                   {},
                                                   m_retry,
                                                   m_shutdownRequested,
                                                   COMPONENT_NAME,
                                                   fmt::format("Synchronize space '{}'", space.name));

    bool changed = false;
    switch (outcome.status)
    {
        case CycleStatus::Updated:
            space.lastSuccessfulUpdate = static_cast<std::uint32_t>(std::time(nullptr));
            space.status = base::SyncStatus::READY;
            changed = true;
            break;

        case CycleStatus::Unchanged: space.status = base::SyncStatus::READY; break;

        case CycleStatus::SkippedConsumerNotReady:
        case CycleStatus::SkippedPreconditionUnmet:
            // Deferred, not failed: the deployed ruleset is still the one in force.
            LOG_DEBUG("[{}] Synchronization of space '{}' deferred: {}", COMPONENT_NAME, space.name, outcome.detail);
            space.status = base::SyncStatus::READY;
            break;

        case CycleStatus::SkippedStopRequested:
        case CycleStatus::SkippedAlreadyRunning:
            // Nothing ran, so nothing was observed.
            space.status = previous;
            break;

        case CycleStatus::FailedTransport:
        case CycleStatus::FailedSink:
        case CycleStatus::FailedConfig:
            LOG_WARNING("[{}] Failed to synchronize space '{}': {}", COMPONENT_NAME, space.name, outcome.detail);
            space.status = base::SyncStatus::FAILED;
            break;
    }

    space.deployment = space.sink->deployment();
    if (space.deployment.enabled.has_value())
    {
        space.policyKnown = true;
        if (*space.deployment.enabled != space.enabled)
        {
            space.enabled = *space.deployment.enabled;
            changed = true;
        }
    }
    return changed;
}

void CMSync::loadState()
{
    auto storePtr = base::utils::lockWeakPtr(m_store, "Store");
    if (!storePtr->existsDoc(STORE_NAME_CMSYNC))
    {
        return;
    }

    const auto doc = storePtr->readDoc(STORE_NAME_CMSYNC);
    if (base::isError(doc))
    {
        throw std::runtime_error(
            fmt::format("Failed to load cmsync state from store: {}", base::getError(doc).message));
    }

    const auto entries = base::getResponse(doc).getArray();
    if (!entries.has_value())
    {
        throw std::runtime_error("Invalid cmsync state document: not an array");
    }

    for (const auto& entry : *entries)
    {
        std::string origin;
        if (entry.getString(origin, JPATH_ORIGIN) != json::RetGet::Success)
        {
            continue;
        }
        for (auto& space : m_spaces)
        {
            if (space.name != origin)
            {
                continue;
            }
            if (const auto ts = entry.getInt64(JPATH_LAST_SUCCESSFUL_UPDATE); ts.has_value())
            {
                space.lastSuccessfulUpdate = static_cast<std::uint32_t>(*ts);
            }
            if (const auto enabled = entry.getBool(JPATH_ENABLED); enabled.has_value())
            {
                space.enabled = *enabled;
                space.policyKnown = true;
            }
        }
    }
}

void CMSync::persistState()
{
    auto storePtr = base::utils::lockWeakPtr(m_store, "Store");

    json::Json doc {};
    doc.setArray();
    for (const auto& space : m_spaces)
    {
        json::Json entry {};
        entry.setString(space.name, JPATH_ORIGIN);
        entry.setInt64(static_cast<int64_t>(space.lastSuccessfulUpdate), JPATH_LAST_SUCCESSFUL_UPDATE);
        // Only a policy read sets it: an unread policy is not a disabled one.
        if (space.policyKnown)
        {
            entry.setBool(space.enabled, JPATH_ENABLED);
        }
        doc.appendJson(entry);
    }

    if (auto error = storePtr->upsertDoc(STORE_NAME_CMSYNC, doc); base::isError(error))
    {
        throw std::runtime_error(
            fmt::format("Failed to dump cmsync state to store: {}", base::getError(error).message));
    }
}

void CMSync::publishStatus()
{
    std::vector<SpaceStatus> statuses;
    statuses.reserve(m_spaces.size());
    for (const auto& space : m_spaces)
    {
        SpaceStatus status;
        status.name = space.name;
        status.status = space.status;
        status.available = space.deployment.available;
        status.hash = space.deployment.hash;
        status.enabled = space.enabled;
        status.lastSuccessfulUpdate = space.lastSuccessfulUpdate;
        statuses.push_back(std::move(status));
    }
    m_status.store(std::move(statuses));
}

void CMSync::requestShutdown()
{
    m_shutdownRequested.store(true);
    for (auto& space : m_spaces)
    {
        space.topic->requestStop();
    }
    LOG_INFO("[{}] Shutdown requested", COMPONENT_NAME);
}

std::vector<SpaceStatus> CMSync::getSpacesStatus() const
{
    return *m_status.load();
}

} // namespace cm::sync
