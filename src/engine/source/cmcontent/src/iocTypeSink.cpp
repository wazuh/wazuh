#include <utility>

#include <fmt/format.h>

#include <base/json.hpp>
#include <base/logging.hpp>
#include <base/utils/stringUtils.hpp>
#include <iockvdb/helpers.hpp>

#include <cmcontent/iocTypeSink.hpp>

namespace cmcontent
{

namespace
{

constexpr std::string_view LOG_MODULE_NAME {"IOC::Sync"};

} // namespace

IocTypeSink::IocTypeSink(std::weak_ptr<ioc::kvdb::IKVDBManager> kvdbManager, std::string iocType)
    : m_kvdbManager(std::move(kvdbManager))
    , m_iocType(std::move(iocType))
    , m_targetDbName(ioc::kvdb::details::getDbNameFromType(m_iocType))
    , m_stagingDbNameForType(fmt::format("iocsync_{}_staging", m_iocType))
{
}

IocTypeSink::~IocTypeSink()
{
    // Deliberately no cleanup here. An interrupted cycle is told to `abort`, which already removes
    // the staging database, so this would only fire on paths where neither commit nor abort ran —
    // and those are exactly the paths the fixed staging name makes recoverable at the next session.
    // Doing KVDB I/O from a destructor during process teardown, against a manager that may itself be
    // shutting down, buys nothing that the next beginSession does not already do.
}

content_manager::SessionDecision IocTypeSink::beginSession(const content_manager::SessionInfo& info) noexcept
{
    using namespace content_manager;

    // Nothing moved remotely. The caller is responsible for noticing that the target database has
    // gone missing and asking for a forced full reload instead — it knows that before the cycle
    // starts, and a NoChange session delivers no documents for this sink to swap in.
    if (info.kind == SessionKind::NoChange)
    {
        return SessionDecision::Skip;
    }

    auto kvdb = m_kvdbManager.lock();
    if (!kvdb)
    {
        return SessionDecision::Abort;
    }

    try
    {
        // One fixed name per type, not a random one. Two cycles for the same type can never run at
        // once — the library refuses the second — so a random suffix bought nothing, and it cost the
        // only thing that matters after a crash: a staging database whose name died with the process
        // is one nothing can ever find again, so every interrupted sync leaked a database
        // permanently. With a fixed name this single call cleans up after both a previous session of
        // this object and a previous run of the whole process.
        discardStaging();

        m_stagingDbName = m_stagingDbNameForType;
        kvdb->add(m_stagingDbName);
        m_storedCount = 0;

        LOG_DEBUG("[{}] Staging database '{}' created for IOC type '{}'", LOG_MODULE_NAME, m_stagingDbName, m_iocType);
        return SessionDecision::Proceed;
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("[{}] Could not create the staging database for IOC type '{}': {}",
                    LOG_MODULE_NAME,
                    m_iocType,
                    e.what());
        m_stagingDbName.clear();
        return SessionDecision::Abort;
    }
    catch (...)
    {
        m_stagingDbName.clear();
        return SessionDecision::Abort;
    }
}

content_manager::PageAck IocTypeSink::acceptPage(const content_manager::ContentPage& page) noexcept
{
    using namespace content_manager;

    if (page.hits == nullptr || m_stagingDbName.empty())
    {
        return PageAck {PageStatus::Accepted, {}};
    }

    auto kvdb = m_kvdbManager.lock();
    if (!kvdb)
    {
        return PageAck {PageStatus::Reject, "the KVDB manager is gone"};
    }

    try
    {
        for (const auto& hit : *page.hits)
        {
            if (!hit.contains("_source") || !hit.at("_source").is_object())
            {
                LOG_WARNING("[{}] Hit without _source for IOC type '{}', skipping", LOG_MODULE_NAME, m_iocType);
                continue;
            }

            const auto& source = hit.at("_source");
            if (!source.contains("document") || !source.at("document").is_object())
            {
                LOG_WARNING("[{}] IOC document without /document object, skipping", LOG_MODULE_NAME);
                continue;
            }

            const auto& document = source.at("document");
            const auto name = document.value("name", std::string {});
            if (name.empty())
            {
                LOG_WARNING("[{}] IOC document without document.name field, skipping", LOG_MODULE_NAME);
                continue;
            }

            // Lower-cased so lookups are case-insensitive: indicators arrive with whatever casing
            // the feed used, and the data they are matched against has its own.
            const auto key = base::utils::string::toLowerCase(name);
            json::Json value {document.dump().c_str()};
            ioc::kvdb::details::updateValueInDB(kvdb, m_stagingDbName, key, value);
            ++m_storedCount;
        }

        // Always Accepted: a staging database has no meaningful intermediate durability, because
        // nothing reads it until the swap and a partial one is thrown away rather than resumed.
        return PageAck {PageStatus::Accepted, {}};
    }
    catch (const std::exception& e)
    {
        return PageAck {PageStatus::Reject, e.what()};
    }
    catch (...)
    {
        return PageAck {PageStatus::Reject, "unknown error while storing IOC documents"};
    }
}

content_manager::CommitResult IocTypeSink::commit(const content_manager::CommitInfo&) noexcept
{
    using namespace content_manager;

    if (m_stagingDbName.empty())
    {
        return CommitResult {CommitStatus::RejectedRetrySame, "no staging database to promote"};
    }

    auto kvdb = m_kvdbManager.lock();
    if (!kvdb)
    {
        return CommitResult {CommitStatus::RejectedRetrySame, "the KVDB manager is gone"};
    }

    try
    {
        if (!kvdb->exists(m_targetDbName))
        {
            kvdb->add(m_targetDbName);
            LOG_INFO("[{}] Created target database '{}'", LOG_MODULE_NAME, m_targetDbName);
        }

        kvdb->hotSwap(m_stagingDbName, m_targetDbName);
        m_stagingDbName.clear();
        m_lastStoredCount = m_storedCount;

        if (m_storedCount == 0)
        {
            LOG_WARNING("[{}] No IOCs found for type '{}'", LOG_MODULE_NAME, m_iocType);
        }

        LOG_INFO("[{}] Synchronized IOC type '{}' ({} entries)", LOG_MODULE_NAME, m_iocType, m_storedCount);
        return CommitResult {CommitStatus::Committed, {}};
    }
    catch (const std::exception& e)
    {
        // RetrySame rather than RetryFull: the failure is in the promotion, not in the content, so
        // the remote hash is still the one to fetch next time. Keeping the old token would be wrong
        // (we never committed), and the library leaves it untouched on this status — which is
        // exactly right, since the token still describes what the target database holds.
        discardStaging();
        LOG_WARNING("[{}] Failed to promote IOC type '{}': {}", LOG_MODULE_NAME, m_iocType, e.what());
        return CommitResult {CommitStatus::RejectedRetrySame, e.what()};
    }
    catch (...)
    {
        discardStaging();
        return CommitResult {CommitStatus::RejectedRetrySame, "unknown error promoting the IOC database"};
    }
}

void IocTypeSink::abort(content_manager::AbortReason, const std::string& detail) noexcept
{
    if (!m_stagingDbName.empty())
    {
        LOG_DEBUG("[{}] Discarding the staging database for IOC type '{}': {}", LOG_MODULE_NAME, m_iocType, detail);
    }
    discardStaging();
}

void IocTypeSink::discardStaging() noexcept
{
    m_stagingDbName.clear();
    m_storedCount = 0;

    auto kvdb = m_kvdbManager.lock();
    if (!kvdb)
    {
        return;
    }

    // Keyed on the type's fixed staging name rather than on whether *this object* opened a session,
    // so it also reclaims what an earlier process left behind. There is exactly one such database
    // per type and nothing else ever reads it, so removing it whenever it exists is unconditionally
    // safe.
    const auto& name = m_stagingDbNameForType;

    try
    {
        if (kvdb->exists(name))
        {
            kvdb->remove(name);
        }
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("[{}] Failed to remove the staging database '{}': {}", LOG_MODULE_NAME, name, e.what());
    }
    catch (...)
    {
        LOG_WARNING("[{}] Failed to remove the staging database '{}'", LOG_MODULE_NAME, name);
    }
}

} // namespace cmcontent
