#include <rawevtindexer/raweventindexer.hpp>

#include <stdexcept>

#include <base/logging.hpp>

namespace raweventindexer
{

RawEventIndexer::RawEventIndexer(std::weak_ptr<wiconnector::IWIndexerConnector> connector,
                                 std::string_view indexName)
    : m_enabled(false)
    , m_connector(std::move(connector))
    , m_indexName(indexName)
{
    if (m_connector.expired())
    {
        throw std::runtime_error("Indexer connector is not available");
    }
}

void RawEventIndexer::index(const std::string& data)
{
    if (!m_enabled.load(std::memory_order_acquire))
    {
        return;
    }

    auto connector = m_connector.lock();
    if (connector)
    {
        try
        {
            connector->index(m_indexName, data);
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Failed to index raw event: {}", e.what());
        }
    }
}

void RawEventIndexer::index(const char* data)
{
    if (!data || *data == '\0')
    {
        return;
    }

    if (!m_enabled.load(std::memory_order_acquire))
    {
        return;
    }

    auto connector = m_connector.lock();
    if (connector)
    {
        try
        {
            connector->index(m_indexName, std::string_view(data));
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Failed to index raw event: {}", e.what());
        }
    }
}

void RawEventIndexer::index(std::string_view data)
{
    if (data.empty())
    {
        return;
    }

    if (!m_enabled.load(std::memory_order_acquire))
    {
        return;
    }

    auto connector = m_connector.lock();
    if (connector)
    {
        try
        {
            connector->index(m_indexName, data);
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Failed to index raw event: {}", e.what());
        }
    }
}

void RawEventIndexer::enable()
{
    m_enabled.store(true, std::memory_order_release);
}

void RawEventIndexer::disable()
{
    m_enabled.store(false, std::memory_order_release);
}

bool RawEventIndexer::isEnabled() const
{
    return m_enabled.load(std::memory_order_acquire);
}

void RawEventIndexer::hotReloadConf(const json::Json& value)
{
    if (!value.isBool())
    {
        throw std::invalid_argument(
            fmt::format("Expected boolean for 'index_raw_events', got: {}", value.str()));
    }

    value.getBool().value() ? enable() : disable();
}

} // namespace raweventindexer
