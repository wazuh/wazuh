/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_DOWNLOADER_HPP
#define _INDEXER_DOWNLOADER_HPP

#include "componentsHelper.hpp"
#include "indexerConnector.hpp"
#include "sharedDefs.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <algorithm>
#include <cctype>
#include <memory>
#include <optional>
#include <string>

class IndexerDownloader final : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
private:
    nlohmann::json m_config;

    static bool isUnsignedInteger(const std::string& value)
    {
        return !value.empty() &&
               std::all_of(value.begin(), value.end(), [](unsigned char character) { return std::isdigit(character); });
    }

    static std::string toJsonPointerPath(const std::string& dottedPath)
    {
        std::string pointerPath;
        pointerPath.reserve(dottedPath.size() + 1);
        pointerPath.push_back('/');

        for (const auto character : dottedPath)
        {
            pointerPath.push_back(character == '.' ? '/' : character);
        }

        return pointerPath;
    }

    nlohmann::json getCursorJson(const nlohmann::json& source, const std::string& cursorField) const
    {
        if (source.contains(cursorField))
        {
            return source.at(cursorField);
        }

        const auto pointerPath = toJsonPointerPath(cursorField);
        const auto jsonPointer = nlohmann::json::json_pointer(pointerPath);
        if (source.contains(jsonPointer))
        {
            return source.at(jsonPointer);
        }

        return nullptr;
    }

    std::string getCursorAsString(const nlohmann::json& source, const std::string& cursorField) const
    {
        const auto cursorValue = getCursorJson(source, cursorField);
        if (cursorValue.is_null())
        {
            return "";
        }

        if (cursorValue.is_string())
        {
            return cursorValue.get<std::string>();
        }

        if (cursorValue.is_number_integer())
        {
            return std::to_string(cursorValue.get<int64_t>());
        }

        if (cursorValue.is_number_unsigned())
        {
            return std::to_string(cursorValue.get<uint64_t>());
        }

        if (cursorValue.is_number_float())
        {
            return std::to_string(cursorValue.get<double>());
        }

        return cursorValue.dump();
    }

    const std::string& getCursorField() const
    {
        return m_config.at("cursorField").get_ref<const std::string&>();
    }

    const std::string& getSortField() const
    {
        return m_config.at("sortField").get_ref<const std::string&>();
    }

    const std::string& getInitialLoadMode() const
    {
        return m_config.at("initialLoadMode").get_ref<const std::string&>();
    }

    std::string getStoredCursor(const UpdaterContext& context) const
    {
        if (!context.spUpdaterBaseContext->spRocksDB)
        {
            return "";
        }

        try
        {
            const auto value =
                context.spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET)
                    .second.ToString();
            return (value == "0") ? "" : value;
        }
        catch (const std::runtime_error&)
        {
            return "";
        }
    }

    void processPage(UpdaterContext& context, const nlohmann::json& hits, const std::string& cursor) const
    {
        nlohmann::json message;
        message["type"] = "indexer";
        message["cursor"] = cursor;
        message["data"] = nlohmann::json::array();

        for (const auto& hit : hits)
        {
            const auto& source = hit.value("_source", hit);

            const auto state = source.value("/document/cveMetadata/state"_json_pointer, std::string {});
            const auto type = (state == "REJECTED") ? "delete" : "create";

            nlohmann::json resource;
            resource["resource"] = source.value("/document/cveMetadata/cveId"_json_pointer, std::string {});
            resource["type"] = type;
            resource["payload"] = source.value("document", nlohmann::json::object());

            const auto cursorField = getCursorField();
            const auto cursorValue = getCursorAsString(source, cursorField);
            if (isUnsignedInteger(cursorValue))
            {
                resource["offset"] = std::stoll(cursorValue);
            }
            else
            {
                resource["offset"] = source.value("offset", 0);
            }

            message["data"].push_back(std::move(resource));
        }

        const auto result = context.spUpdaterBaseContext->fileProcessingCallback(message.dump());
        if (!std::get<2>(result))
        {
            throw std::runtime_error("IndexerDownloader: fileProcessingCallback returned failure");
        }
    }

    void runQuery(UpdaterContext& context, const std::optional<std::string>& minCursor) const
    {
        const auto& indexName = m_config.at("indexer").at("index").get_ref<const std::string&>();
        const size_t pageSize = m_config.at("indexer").value("pageSize", 1000u);
        const auto& cursorField = getCursorField();
        const auto& sortField = getSortField();

        IndexerConnectorSync syncConnector(m_config.at("indexer"));

        nlohmann::json query;
        if (minCursor.has_value())
        {
            if (isUnsignedInteger(minCursor.value()))
            {
                query["query"]["range"][cursorField]["gt"] = std::stoull(minCursor.value());
            }
            else
            {
                query["query"]["range"][cursorField]["gt"] = minCursor.value();
            }
        }
        else
        {
            query["query"]["match_all"] = nlohmann::json::object();
        }
        query["sort"] = nlohmann::json::array({sortField, "_id"});
        query["size"] = pageSize;

        std::string currentCursor = minCursor.value_or("");

        syncConnector.executeSearchQueryWithPagination(
            indexName,
            query,
            [&](const nlohmann::json& response)
            {
                if (!response.contains("hits") || !response.at("hits").contains("hits"))
                {
                    return;
                }

                const auto& hits = response.at("hits").at("hits");
                if (hits.empty())
                {
                    return;
                }

                const auto& lastHit = hits.back();
                if (lastHit.contains("_source"))
                {
                    const auto cursorValue = getCursorAsString(lastHit.at("_source"), cursorField);
                    if (!cursorValue.empty())
                    {
                        currentCursor = cursorValue;
                    }
                }

                processPage(context, hits, currentCursor);
            });

        if (!currentCursor.empty())
        {
            context.data["cursor"] = currentCursor;
        }
    }

public:
    explicit IndexerDownloader(const nlohmann::json& config)
        : m_config(config)
    {
    }

    std::shared_ptr<UpdaterContext> handleRequest(std::shared_ptr<UpdaterContext> context) override
    {
        logDebug1(WM_CONTENTUPDATER, "IndexerDownloader - Starting process");

        if (!m_config.contains("indexer") || !m_config.at("indexer").is_object())
        {
            throw std::invalid_argument("IndexerDownloader: missing 'indexer' configuration");
        }

        if (!m_config.at("indexer").contains("index") || !m_config.at("indexer").at("index").is_string() ||
            m_config.at("indexer").at("index").get<std::string>().empty())
        {
            throw std::invalid_argument("IndexerDownloader: missing 'indexer.index' configuration");
        }

        if (!m_config.contains("cursorField") || !m_config.at("cursorField").is_string() ||
            m_config.at("cursorField").get<std::string>().empty())
        {
            throw std::invalid_argument("IndexerDownloader: missing 'cursorField' configuration");
        }

        if (!m_config.contains("sortField") || !m_config.at("sortField").is_string() ||
            m_config.at("sortField").get<std::string>().empty())
        {
            throw std::invalid_argument("IndexerDownloader: missing 'sortField' configuration");
        }

        if (!m_config.contains("initialLoadMode") || !m_config.at("initialLoadMode").is_string() ||
            m_config.at("initialLoadMode").get<std::string>().empty())
        {
            throw std::invalid_argument("IndexerDownloader: missing 'initialLoadMode' configuration");
        }

        const auto& initialLoadMode = getInitialLoadMode();
        if (initialLoadMode == "pit-search-after")
        {
            logDebug2(WM_CONTENTUPDATER,
                      "IndexerDownloader: initialLoadMode='pit-search-after' requested; using search-after pagination");
        }

        const auto lastCursor = getStoredCursor(*context);
        if (lastCursor.empty())
        {
            runQuery(*context, std::nullopt);
        }
        else
        {
            runQuery(*context, lastCursor);
        }

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(std::move(context));
    }
};

#endif // _INDEXER_DOWNLOADER_HPP
