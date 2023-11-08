/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * August 24, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "rsyncImplementation.h"
#include "rsync_exception.h"
#include "makeUnique.h"
#include "stringHelper.h"
#include "hashHelper.h"
#include "loggerHelper.h"
#include "messageCreatorFactory.h"
#include "rsync.hpp"
#include "synchronizationController.hpp"

using namespace RSync;

SynchronizationController RSyncImplementation::m_synchronizationController;

void RSyncImplementation::release()
{
    std::lock_guard<std::mutex> lock{ m_mutex };
    m_synchronizationController.clear();

    for (const auto& ctx : m_remoteSyncContexts)
    {
        m_registrationController.removeComponentByHandle(ctx.first);
        ctx.second->m_msgDispatcher->rundown();
    }

    m_remoteSyncContexts.clear();
}

void RSyncImplementation::releaseContext(const RSYNC_HANDLE handle)
{
    m_registrationController.removeComponentByHandle(handle);
    remoteSyncContext(handle)->m_msgDispatcher->rundown();
    std::lock_guard<std::mutex> lock{ m_mutex };
    m_synchronizationController.stop(handle);
    m_remoteSyncContexts.erase(handle);
}

RSYNC_HANDLE RSyncImplementation::create(const unsigned int threadPoolSize, const size_t maxQueueSize)
{
    const auto spRSyncContext
    {
        std::make_shared<RSyncContext>(threadPoolSize, maxQueueSize)
    };
    const RSYNC_HANDLE handle{ spRSyncContext.get() };
    std::lock_guard<std::mutex> lock{m_mutex};
    m_remoteSyncContexts[handle] = spRSyncContext;
    return handle;
}

void RSyncImplementation::startRSync(const RSYNC_HANDLE handle,
                                     const std::shared_ptr<DBSyncWrapper>& spDBSyncWrapper,
                                     const nlohmann::json& startConfiguration,
                                     const ResultCallback callbackWrapper)
{
    const auto ctx                  { remoteSyncContext(handle) };

    const auto& jsStartParamsTable  { startConfiguration.at("table")              };
    const auto& firstQuery          { startConfiguration.find("first_query")      };
    const auto& lastQuery           { startConfiguration.find("last_query")       };

    if (!jsStartParamsTable.empty() && firstQuery != startConfiguration.end() && lastQuery != startConfiguration.end())
    {
        const auto& jsFirstLastOutput { executeSelectQuery(spDBSyncWrapper, jsStartParamsTable, firstQuery.value(), lastQuery.value()) };
        const auto& jsonFirstQueryResult { jsFirstLastOutput.at("first_result") };
        const auto& jsonLastQueryResult  { jsFirstLastOutput.at("last_result") };

        auto messageCreator { FactoryMessageCreator<SplitContext, MessageType::CHECKSUM>::create() };

        ChecksumContext checksumCtx {};
        // In this case, 'size' field will not be used because of the checksum type (CHECKSUM_COMPLETE).
        checksumCtx.size = 0;
        checksumCtx.rightCtx.id = std::time(nullptr);

        if (!jsonFirstQueryResult.empty() && !jsonLastQueryResult.empty())
        {
            const auto& indexField { startConfiguration.at("index").get_ref<const std::string&>() };
            const auto& begin      { jsonFirstQueryResult.at(indexField) };
            const auto& end        { jsonLastQueryResult.at(indexField)  };

            checksumCtx.type           = CHECKSUM_COMPLETE;
            checksumCtx.rightCtx.type  = IntegrityMsgType::INTEGRITY_CHECK_GLOBAL;

            if (begin.is_string())
            {
                checksumCtx.rightCtx.begin = begin;
                checksumCtx.rightCtx.end   = end;
                fillChecksum(spDBSyncWrapper, startConfiguration, begin, end, checksumCtx);
            }
            else
            {
                const auto beginNumber{begin.get<unsigned long>()};
                const auto endNumber{end.get<unsigned long>()};
                const auto beginString{std::to_string(beginNumber)};
                const auto endString{std::to_string(endNumber)};
                checksumCtx.rightCtx.begin = beginString;
                checksumCtx.rightCtx.end   = endString;
                fillChecksum(spDBSyncWrapper, startConfiguration, beginString, endString, checksumCtx);
            }
        }
        else
        {
            checksumCtx.rightCtx.type = IntegrityMsgType::INTEGRITY_CLEAR;
        }

        m_synchronizationController.start(handle, jsStartParamsTable, checksumCtx.rightCtx.id);
        // rightCtx will have the final checksum based on fillChecksum method. After processing all checksum select data
        // checksumCtx.rightCtx will have the needed (final) information
        messageCreator->send(callbackWrapper, startConfiguration, checksumCtx.rightCtx);

        logDebug2(RSYNC_LOG_TAG, "Remote sync started: %s", RSync::IntegrityCommands[checksumCtx.rightCtx.type].c_str());
    }
    else
    {
        throw rsync_error { INPUT_JSON_INCOMPLETE };
    }
}

std::shared_ptr<RSyncImplementation::RSyncContext> RSyncImplementation::remoteSyncContext(const RSYNC_HANDLE handle)
{
    std::lock_guard<std::mutex> lock{m_mutex};
    const auto it{ m_remoteSyncContexts.find(handle) };

    if (it == m_remoteSyncContexts.end())
    {
        throw rsync_error { INVALID_HANDLE };
    }

    return it->second;
}

void RSyncImplementation::registerSyncId(const RSYNC_HANDLE handle,
                                         const std::string& messageHeaderID,
                                         const std::shared_ptr<DBSyncWrapper>& spDBSyncWrapper,
                                         const nlohmann::json& syncConfiguration,
                                         const ResultCallback callbackWrapper)
{
    if (isComponentRegistered(messageHeaderID))
    {
        throw rsync_error { COMPONENT_ALREADY_REGISTERED };
    }

    const auto ctx { remoteSyncContext(handle) };
    const SyncMsgBodyType syncMessageType { SyncMsgBodyTypeMap.at(syncConfiguration.at("decoder_type")) };

    ctx->m_msgDispatcher->setMessageDecoderType(messageHeaderID, syncMessageType);

    const auto registerCallback
    {
        [spDBSyncWrapper, syncConfiguration, callbackWrapper, handle] (const SyncInputData & syncData)
        {
            try
            {
                m_synchronizationController.checkId(handle, syncConfiguration.at("table"), syncData.id);

                if (0 == syncData.command.compare("checksum_fail"))
                {
                    sendChecksumFail(spDBSyncWrapper, syncConfiguration, callbackWrapper, syncData);
                }
                else if (0 == syncData.command.compare("no_data"))
                {
                    sendAllData(spDBSyncWrapper, syncConfiguration, callbackWrapper, syncData);
                }
                else
                {
                    throw rsync_error { INVALID_OPERATION };
                }
            }
            catch (const std::exception& e)
            {
                std::cerr << e.what() << '\n';
            }

        }
    };

    ctx->m_msgDispatcher->addCallback(messageHeaderID, registerCallback);
    m_registrationController.initComponentByHandle(handle, messageHeaderID);
}


void RSyncImplementation::push(const RSYNC_HANDLE handle, const std::vector<unsigned char>& data)
{
    const auto spRSyncContext
    {
        remoteSyncContext(handle)
    };
    spRSyncContext->m_msgDispatcher->push(data);
}

void RSyncImplementation::sendChecksumFail(const std::shared_ptr<DBSyncWrapper>& spDBSyncWrapper,
                                           const nlohmann::json& jsonSyncConfiguration,
                                           const ResultCallback callbackWrapper,
                                           const SyncInputData syncData)
{
    const auto size { getRangeCount(spDBSyncWrapper, jsonSyncConfiguration, syncData) };

    if (1 == size && syncData.begin.compare(syncData.end) == 0)
    {
        const auto& rowData{ getRowData(spDBSyncWrapper, jsonSyncConfiguration, syncData.begin) };

        FactoryMessageCreator<nlohmann::json, MessageType::ROW_DATA>::create()->send(callbackWrapper, jsonSyncConfiguration, rowData);
    }
    else if (1 < size)
    {
        auto messageCreator { FactoryMessageCreator<SplitContext, MessageType::CHECKSUM>::create() };

        ChecksumContext checksumCtx;
        checksumCtx.type = CHECKSUM_SPLIT;
        checksumCtx.size = size;
        checksumCtx.leftCtx.id = syncData.id;
        checksumCtx.leftCtx.type = IntegrityMsgType::INTEGRITY_CHECK_LEFT;
        checksumCtx.leftCtx.begin = syncData.begin;

        checksumCtx.rightCtx.id = syncData.id;
        checksumCtx.rightCtx.type = IntegrityMsgType::INTEGRITY_CHECK_RIGHT;
        checksumCtx.rightCtx.end = syncData.end;
        fillChecksum(spDBSyncWrapper, jsonSyncConfiguration, syncData.begin, syncData.end, checksumCtx);

        messageCreator->send(callbackWrapper, jsonSyncConfiguration, checksumCtx.leftCtx);
        messageCreator->send(callbackWrapper, jsonSyncConfiguration, checksumCtx.rightCtx);
    }
    else
    {
        throw rsync_error { UNEXPECTED_SIZE };
    }
}

size_t RSyncImplementation::getRangeCount(const std::shared_ptr<DBSyncWrapper>& spDBSyncWrapper,
                                          const nlohmann::json& jsonSyncConfiguration,
                                          const SyncInputData& syncData)
{
    nlohmann::json selectData;
    selectData["table"] = jsonSyncConfiguration.at("table");
    auto& queryParam { selectData["query"] };
    const auto& querySelect { jsonSyncConfiguration.at("count_range_query_json") };

    const auto& countFieldName { querySelect.at("count_field_name").get_ref<const std::string&>() };

    size_t size { 0ull };
    ResultCallbackData callback
    {
        [&size, &countFieldName] (ReturnTypeCallback /*returnType*/, const nlohmann::json & resultJSON)
        {
            size = resultJSON.at(countFieldName);
        }
    };

    auto rowFilter { querySelect.at("row_filter").get_ref<const std::string&>() } ;
    Utils::replaceFirst(rowFilter, "?", syncData.begin);
    Utils::replaceFirst(rowFilter, "?", syncData.end);

    queryParam["row_filter"] = rowFilter;
    queryParam["column_list"] = querySelect.at("column_list");
    queryParam["distinct_opt"] = querySelect.at("distinct_opt");
    queryParam["order_by_opt"] = querySelect.at("order_by_opt");

    spDBSyncWrapper->select(selectData, callback);

    return size;
}


void RSyncImplementation::fillChecksum(const std::shared_ptr<DBSyncWrapper>& spDBSyncWrapper,
                                       const nlohmann::json& jsonSyncConfiguration,
                                       const std::string& begin,
                                       const std::string& end,
                                       ChecksumContext& ctx)
{
    nlohmann::json selectData;
    selectData["table"] = jsonSyncConfiguration.at("table");

    const auto& querySelect { jsonSyncConfiguration.at("range_checksum_query_json") };
    const auto& checksumFieldName { jsonSyncConfiguration.at("checksum_field").get_ref<const std::string&>() };
    auto index { 1ull };
    const auto middle { ctx.size / 2 };

    std::unique_ptr<Utils::HashData> hash{ std::make_unique<Utils::HashData>() };
    ResultCallbackData callback
    {
        [&] (ReturnTypeCallback /*callback*/, const nlohmann::json & resultJSON)
        {
            const auto checksumValue { resultJSON.at(checksumFieldName).get_ref<const std::string&>() };
            hash->update(checksumValue.data(), checksumValue.size());

            if (CHECKSUM_SPLIT == ctx.type)
            {
                const auto& indexFieldName { jsonSyncConfiguration.at("index").get_ref<const std::string&>() };
                const auto& result{resultJSON.at(indexFieldName)};

                if (middle + 1 == index)
                {
                    ctx.rightCtx.begin = result.is_string() ? result.get_ref<const std::string&>() : std::to_string(result.get<unsigned long>());
                    ctx.leftCtx.tail = ctx.rightCtx.begin;
                }
                else if (middle == index)
                {
                    ctx.leftCtx.end = result.is_string() ? result.get_ref<const std::string&>() : std::to_string(result.get<unsigned long>());
                    ctx.leftCtx.checksum = Utils::asciiToHex(hash->hash());
                    hash = std::make_unique<Utils::HashData>();
                }

                ++index;
            }
        }
    };

    auto rowFilter { querySelect.at("row_filter").get_ref<const std::string&>() } ;
    Utils::replaceFirst(rowFilter, "?", begin);
    Utils::replaceFirst(rowFilter, "?", end);

    auto& queryParam { selectData["query"] };
    queryParam["row_filter"] = rowFilter;
    queryParam["column_list"] = querySelect.at("column_list");
    queryParam["distinct_opt"] = querySelect.at("distinct_opt");
    queryParam["order_by_opt"] = querySelect.at("order_by_opt");

    spDBSyncWrapper->select(selectData, callback);

    // rightCtx field will have the final checksum
    ctx.rightCtx.checksum = Utils::asciiToHex(hash->hash());
}

nlohmann::json RSyncImplementation::getRowData(const std::shared_ptr<DBSyncWrapper>& spDBSyncWrapper,
                                               const nlohmann::json& jsonSyncConfiguration,
                                               const std::string& index)
{
    nlohmann::json rowData;
    ResultCallbackData callback
    {
        [&rowData] (ReturnTypeCallback /*callbackType*/, const nlohmann::json & resultJSON)
        {
            rowData = resultJSON;
        }
    };

    nlohmann::json selectData;
    selectData["table"] = jsonSyncConfiguration.at("table");
    auto& queryParam { selectData["query"] };

    nlohmann::json querySelect;
    std::string rowFilter;

    if (!index.empty())
    {
        // Register sync flow
        querySelect = jsonSyncConfiguration.at("row_data_query_json");
        rowFilter = querySelect.at("row_filter").get_ref<const std::string&>();
        Utils::replaceFirst(rowFilter, "?", index);
    }
    else
    {
        // Start sync flow
        querySelect = jsonSyncConfiguration.at("query");
        rowFilter = querySelect.at("row_filter").get_ref<const std::string&>();
    }

    queryParam["row_filter"]   = rowFilter;
    queryParam["column_list"]  = querySelect.at("column_list");
    queryParam["distinct_opt"] = querySelect.at("distinct_opt");
    queryParam["order_by_opt"] = querySelect.at("order_by_opt");

    spDBSyncWrapper->select(selectData, callback);
    return rowData;
}

nlohmann::json RSyncImplementation::executeSelectQuery(const std::shared_ptr<DBSyncWrapper>& spDBSyncWrapper,
                                                       const std::string& table,
                                                       const nlohmann::json& jsFirstQuery,
                                                       const nlohmann::json& jsLastQuery)
{
    nlohmann::json jsonOutput;

    if (!jsFirstQuery.empty() && !jsLastQuery.empty())
    {
        nlohmann::json jsSelectFirstQuery;
        nlohmann::json jsSelectLastQuery;
        jsSelectFirstQuery["table"] = table;
        jsSelectLastQuery["table"] = table;
        jsSelectFirstQuery["query"] = jsFirstQuery;
        jsSelectLastQuery["query"] = jsLastQuery;
        jsonOutput["first_result"] = getRowData(spDBSyncWrapper, jsSelectFirstQuery);
        jsonOutput["last_result"]  = getRowData(spDBSyncWrapper, jsSelectLastQuery);
    }

    return jsonOutput;
}

void RSyncImplementation::sendAllData(const std::shared_ptr<DBSyncWrapper>& spDBSyncWrapper,
                                      const nlohmann::json& jsonSyncConfiguration,
                                      const ResultCallback callbackWrapper,
                                      const SyncInputData& syncData)
{
    const auto& messageCreator { FactoryMessageCreator<nlohmann::json, MessageType::ROW_DATA>::create() };
    ResultCallbackData callback
    {
        [&callbackWrapper, &messageCreator, &jsonSyncConfiguration] (ReturnTypeCallback /*callbackType*/, const nlohmann::json & resultJSON)
        {
            const auto component { jsonSyncConfiguration.at("component").get_ref<const std::string&>() };

            if (RSyncImplementation::instance().isComponentRegistered(component))
            {
                messageCreator->send(callbackWrapper, jsonSyncConfiguration, resultJSON);
            }
            else
            {
                throw std::runtime_error("Synchronization cancelled, component inactivated");
            }
        }
    };

    nlohmann::json selectData;
    selectData["table"] = jsonSyncConfiguration.at("table");
    const auto& querySelect { jsonSyncConfiguration.at("no_data_query_json") };

    auto& queryParam { selectData["query"] };

    auto rowFilter { querySelect.at("row_filter").get_ref<const std::string&>() } ;
    Utils::replaceFirst(rowFilter, "?", syncData.begin);
    Utils::replaceFirst(rowFilter, "?", syncData.end);

    queryParam["row_filter"] = rowFilter;
    queryParam["column_list"] = querySelect.at("column_list");
    queryParam["distinct_opt"] = querySelect.at("distinct_opt");
    queryParam["order_by_opt"] = querySelect.at("order_by_opt");

    spDBSyncWrapper->select(selectData, callback);

}

bool RSyncImplementation::isComponentRegistered(const std::string& component)
{
    return m_registrationController.isComponentRegistered(component);
}
