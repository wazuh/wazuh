#include <exception>
#include <utility>

#include "indexersettingssource.hpp"

namespace remoteconf
{

IndexerSettingsSource::IndexerSettingsSource(std::shared_ptr<wiconnector::IWIndexerConnector> connector)
    : m_connector(std::move(connector))
{
}

SettingsFetchResult IndexerSettingsSource::fetchSettings()
{
    if (!m_connector)
    {
        return {FetchStatus::TransportError, {}, "Indexer connector is null"};
    }

    try
    {
        const json::Json query {R"({"term":{"_id":"1"}})"};
        const json::Json sourceFilter {R"({"includes":[],"excludes":[]})"};

        const auto response = m_connector->search(INDEX_NAME, 1U, query, sourceFilter);

        const auto hits = response.getArray("/hits");
        if (!hits.has_value())
        {
            return {FetchStatus::InvalidPayload, {}, "hits field missing or not an array"};
        }

        if (hits->empty())
        {
            return {FetchStatus::NotFound, {}, "Settings document not found"};
        }

        const auto source = hits->at(0).getJson("/_source/engine");
        if (!source.has_value() || !source->isObject())
        {
            return {FetchStatus::InvalidPayload, {}, "_source/engine missing or not an object"};
        }

        return {FetchStatus::Success, source.value(), {}};
    }
    catch (const std::exception& e)
    {
        return {FetchStatus::TransportError, {}, e.what()};
    }
}

std::shared_ptr<ISettingsSource> makeIndexerSettingsSource(std::shared_ptr<wiconnector::IWIndexerConnector> connector)
{
    return std::make_shared<IndexerSettingsSource>(std::move(connector));
}

} // namespace remoteconf
