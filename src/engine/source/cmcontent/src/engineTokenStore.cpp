#include <utility>

#include <base/logging.hpp>

#include <cmcontent/engineTokenStore.hpp>

namespace cmcontent
{

EngineTokenStore::EngineTokenStore(Loader loader, Storer storer)
    : m_loader(std::move(loader))
    , m_storer(std::move(storer))
{
}

std::string EngineTokenStore::load(std::string_view topic) noexcept
{
    if (!m_loader)
    {
        return {};
    }

    try
    {
        return m_loader(topic);
    }
    catch (const std::exception& e)
    {
        // An unreadable token is not fatal: it degrades to "no token", which makes the next cycle a
        // full reload. Propagating would cross the DSO boundary, which the contract forbids.
        LOG_WARNING("[cmcontent] Failed to read the content token for '{}': {}", topic, e.what());
        return {};
    }
    catch (...)
    {
        LOG_WARNING("[cmcontent] Failed to read the content token for '{}'", topic);
        return {};
    }
}

bool EngineTokenStore::store(std::string_view topic, std::string_view token) noexcept
{
    if (!m_storer)
    {
        return false;
    }

    try
    {
        return m_storer(topic, token);
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("[cmcontent] Failed to persist the content token for '{}': {}", topic, e.what());
        return false;
    }
    catch (...)
    {
        LOG_WARNING("[cmcontent] Failed to persist the content token for '{}'", topic);
        return false;
    }
}

bool EngineTokenStore::clear(std::string_view topic) noexcept
{
    // An empty hash is exactly what "nothing committed yet" looks like in both state documents, so
    // clearing is a store of "" rather than a separate operation.
    return store(topic, {});
}

} // namespace cmcontent
