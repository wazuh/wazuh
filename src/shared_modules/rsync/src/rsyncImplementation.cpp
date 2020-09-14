/*
 * Wazuh RSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
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
#include "messageCreatorFactory.h"

using namespace RSync;

void RSyncImplementation::release()
{
    std::lock_guard<std::mutex> lock{ m_mutex };
    m_remoteSyncContexts.clear();
}

bool RSyncImplementation::releaseContext(const RSYNC_HANDLE handle)
{
    std::lock_guard<std::mutex> lock{ m_mutex };
    return 1 == m_remoteSyncContexts.erase(handle);
}

RSYNC_HANDLE RSyncImplementation::create()
{
    const auto spRSyncContext
    {
        std::make_shared<RSyncContext>()
    };
    const RSYNC_HANDLE handle{ spRSyncContext.get() };
    std::lock_guard<std::mutex> lock{m_mutex};
    m_remoteSyncContexts[handle] = spRSyncContext;
    return handle;
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


void callbackDBSync(ReturnTypeCallback /*result_type*/, const cJSON* result_json, void* user_data)
{
    std::function<void(const nlohmann::json&)>* callback = static_cast<std::function<void(const nlohmann::json&)>*>(user_data);
    const std::unique_ptr<char, CJsonDeleter> spJsonBytes{ cJSON_PrintUnformatted(result_json) };
    const auto json { nlohmann::json::parse(spJsonBytes.get()) };
    (*callback)(json);
}

void RSyncImplementation::registerSyncId(const RSYNC_HANDLE handle, 
                                         const std::string& message_header_id,
                                         const std::shared_ptr<DBSyncImplementation>& spDBSyncImplementation, 
                                         const char* sync_configuration, 
                                         const ResultCallback callbackWrapper)
{
    const auto ctx { remoteSyncContext(handle) };
    const auto json_sync_configuration { nlohmann::json::parse(sync_configuration)[0] };
    
    const SyncMsgBodyType sync_message_type { SyncMsgBodyTypeMap.at(json_sync_configuration.at("decoder_type")) };
    
    ctx->m_msgDispatcher.setMessageDecoderType(message_header_id, sync_message_type);
    
    const auto registerCallback
    {
        [spDBSyncImplementation, json_sync_configuration, callbackWrapper] (const SyncInputData syncData)
        {
            if (0 == syncData.command.compare("checksum_fail"))
            {
                const auto size { getRangeCount(spDBSyncImplementation, json_sync_configuration.at("count_range_query_json"), syncData) };
                
                if (1 == size)
                {
                    const auto& rowDataQueryConfig { json_sync_configuration.at("row_data_query_json") };
                    const auto& rowData{ getRowData(spDBSyncImplementation, rowDataQueryConfig, syncData.begin) };

                    FactoryMessageCreator<nlohmann::json, MessageType::ROW_DATA>::create()->send(callbackWrapper, rowDataQueryConfig, rowData);
                }
                else if (1 < size)
                {
                    const auto end { std::stoull(syncData.end) };
                    const auto& rangeChecksumQueryConfig { json_sync_configuration.at("range_checksum_query_json") };

                    auto messageCreator { FactoryMessageCreator<std::string, MessageType::CHECKSUM>::create() };

                    const auto& checksumsLeft { getChecksum(spDBSyncImplementation, rangeChecksumQueryConfig, syncData.begin, std::to_string(end/2)) };
                    messageCreator->send(callbackWrapper, rangeChecksumQueryConfig, checksumsLeft);

                    const auto& checksumsRight { getChecksum(spDBSyncImplementation, rangeChecksumQueryConfig, std::to_string(end/2+1), syncData.end) };
                    messageCreator->send(callbackWrapper, rangeChecksumQueryConfig, checksumsRight);
                }
                else
                {
                    throw rsync_error { UNEXPECTED_SIZE };
                }
            } 
            else if (0 == syncData.command.compare("no_data"))
            {
                sendAllData(spDBSyncImplementation, json_sync_configuration.at("no_data_query_json"), callbackWrapper);
            }
            else 
            {
                throw rsync_error { INVALID_OPERATION };
            }
        }
    };
    ctx->m_msgDispatcher.addCallback(message_header_id, registerCallback);
}


size_t RSyncImplementation::getRangeCount(const std::shared_ptr<DBSyncImplementation>& spDBSyncImplementation, 
                                          const nlohmann::json& rangeCountQuery, 
                                          const SyncInputData& syncData)
{
    nlohmann::json selectData;
    selectData["table"] = rangeCountQuery.at("table");
    auto& queryParam { selectData["query"] };
    const auto& querySelect { rangeCountQuery["query"] };
    
    const auto& countFieldName { querySelect.at("count_field_name").get_ref<const std::string&>() };

    size_t size { 0ull };
    auto sizeRange
    {
        [&size, &countFieldName] (const nlohmann::json& resultJSON)
        {
            const auto countValue { resultJSON.at(countFieldName) };
            if (countValue.is_number_unsigned())
            {
                size = countValue.get<uint64_t>();
            }
            else 
            {
                throw rsync_error { UNEXPECTED_RANGE_COUNT };
            }
        }
    };

    auto rowFilter { querySelect.at("row_filter").get_ref<const std::string&>() } ;
    Utils::replaceFirst(rowFilter, "?", syncData.begin);
    Utils::replaceFirst(rowFilter, "?", syncData.end);
    
    queryParam["row_filter"] = rowFilter;
    queryParam["colum_list"] = querySelect.at("colum_list");
    queryParam["distinct_opt"] = querySelect.at("distinct_opt");
    queryParam["order_by_opt"] = querySelect.at("order_by_opt");
    
    std::cout << selectData.dump() << std::endl;

    const std::unique_ptr<cJSON, CJsonDeleter> spJson{ cJSON_Parse(selectData.dump().c_str()) };
    spDBSyncImplementation->select(spJson.get(), { callbackDBSync, &sizeRange });

    return size;
}


std::string RSyncImplementation::getChecksum(const std::shared_ptr<DBSyncImplementation>& spDBSyncImplementation, 
                                             const nlohmann::json& rangeQuery,
                                             const std::string& begin,
                                             const std::string& end) 
{
    nlohmann::json selectData;
    selectData["table"] = rangeQuery.at("table");
    auto& queryParam { selectData["query"] };
    const auto& querySelect { rangeQuery["query"] };

    const auto& checksumFieldName { querySelect.at("checksum_field_name").get_ref<const std::string&>() };
    Utils::HashData hash{ Utils::HashType::Sha256 };
    auto calcChecksum
    {
        [&hash, &checksumFieldName] (const nlohmann::json& resultJSON)
        {
            const auto checksumValue { resultJSON.at(checksumFieldName) };
            if (checksumValue.is_string())
            {
                const auto& checksumRow { checksumValue.get_ref<const std::string&>() }; 
                hash.update(checksumRow.data(), checksumRow.size());
            }
            else
            {
                throw rsync_error { UNEXPECTED_CHECKSUM };
            }            
        }
    };

    auto rowFilter { querySelect.at("row_filter").get_ref<const std::string&>() } ;
    Utils::replaceFirst(rowFilter, "?", begin);
    Utils::replaceFirst(rowFilter, "?", end);
    
    queryParam["row_filter"] = rowFilter;
    queryParam["colum_list"] = querySelect.at("colum_list");
    queryParam["distinct_opt"] = querySelect.at("distinct_opt");
    queryParam["order_by_opt"] = querySelect.at("order_by_opt");

    std::cout << selectData.dump() << std::endl;

    const std::unique_ptr<cJSON, CJsonDeleter> spJson{ cJSON_Parse(selectData.dump().c_str()) };
    spDBSyncImplementation->select(spJson.get(), { callbackDBSync, &calcChecksum });

    return Utils::asciiToHex(hash.hash());
}

nlohmann::json RSyncImplementation::getRowData(const std::shared_ptr<DBSyncImplementation>& spDBSyncImplementation, 
                                               const nlohmann::json& rowQuery,
                                               const std::string& index)
{
    nlohmann::json rowData;
    auto getRowData
    {
        [&rowData] (const nlohmann::json& resultJSON)
        {
            rowData = resultJSON;       
        }
    };

    nlohmann::json selectData;
    selectData["table"] = rowQuery.at("table");
    auto& queryParam { selectData["query"] };
    const auto& querySelect { rowQuery["query"] };

    auto rowFilter { querySelect.at("row_filter").get_ref<const std::string&>() } ;
    Utils::replaceFirst(rowFilter, "?", index);
    
    queryParam["row_filter"] = rowFilter;
    queryParam["colum_list"] = querySelect.at("colum_list");
    queryParam["distinct_opt"] = querySelect.at("distinct_opt");
    queryParam["order_by_opt"] = querySelect.at("order_by_opt");

    const std::unique_ptr<cJSON, CJsonDeleter> spJson{ cJSON_Parse(selectData.dump().c_str()) };

    spDBSyncImplementation->select(spJson.get(), { callbackDBSync, &getRowData });
    return rowData;
}

void RSyncImplementation::sendAllData(const std::shared_ptr<DBSyncImplementation>& spDBSyncImplementation, 
                                      const nlohmann::json& noDataQuery,
                                      const ResultCallback callbackWrapper)
{
    const auto& messageCreator { FactoryMessageCreator<nlohmann::json, MessageType::ROW_DATA>::create() };
    auto sendRowData
    {
        [&callbackWrapper, &messageCreator, &noDataQuery] (const nlohmann::json& resultJSON)
        {
            messageCreator->send(callbackWrapper, noDataQuery, resultJSON);  
        }
    };

    nlohmann::json selectData;
    selectData["table"] = noDataQuery.at("table");
    const auto& querySelect { noDataQuery["query"] };

    auto& queryParam { selectData["query"] };
       
    queryParam["row_filter"] = querySelect.at("row_filter");
    queryParam["colum_list"] = querySelect.at("colum_list");
    queryParam["distinct_opt"] = querySelect.at("distinct_opt");
    queryParam["order_by_opt"] = querySelect.at("order_by_opt");

    const std::unique_ptr<cJSON, CJsonDeleter> spJson{ cJSON_Parse(selectData.dump().c_str()) };
    spDBSyncImplementation->select(spJson.get(), { callbackDBSync, &sendRowData });
    
}