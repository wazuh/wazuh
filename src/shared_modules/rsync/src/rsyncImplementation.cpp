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
                                         const DBSYNC_HANDLE dbsync_handle, 
                                         const char* sync_configuration, 
                                         const ResultCallback callbackWrapper)
{
    const auto ctx { remoteSyncContext(handle) };
    const auto json_sync_configuration { nlohmann::json::parse(sync_configuration)[0] };
    
    const SyncMsgBodyType sync_message_type { SyncMsgBodyTypeMap.at(json_sync_configuration.at("decoder_type")) };
    
    ctx->m_msgDispatcher.setMessageDecoderType(message_header_id, sync_message_type);
    
    const auto registerCallback
    {
        [this, dbsync_handle, json_sync_configuration, callbackWrapper] (const SyncInputData syncData)
        {
            if (0 == syncData.command.compare("checksum_fail"))
            {
                const auto size { getRangeCount(dbsync_handle, json_sync_configuration.at("get_count_range_query_json"), syncData) };
                
                if (1 == size)
                {
                    std::string response;
                    callbackWrapper(response);
                }
                else if (1 < size)
                {
                    const auto end { std::stoull(syncData.end) };
                    const auto& checksumsLeft { getChecksums(dbsync_handle, json_sync_configuration.at("get_range_checksum_query_json"), syncData.begin, std::to_string(end/2)) };

                    const auto& checksumsRight { getChecksums(dbsync_handle, json_sync_configuration.at("get_range_checksum_query_json"), std::to_string(end/2+1), syncData.end) };

                    std::string response;
                    callbackWrapper(response);
                }
                else
                {
                    throw rsync_error { UNEXPECTED_SIZE };
                }
            } 
            else if (0 == syncData.command.compare("no_data"))
            {
                //fim_sync_send_list(begin, end);
            }
            else 
            {
                throw rsync_error { INVALID_OPERATION };
            }
        }
    };
    ctx->m_msgDispatcher.addCallback(message_header_id, registerCallback);
}


size_t RSyncImplementation::getRangeCount(const DBSYNC_HANDLE dbsync_handle, 
                                          const nlohmann::json& getRangeCountQuery, 
                                          const SyncInputData& syncData)
{
    nlohmann::json selectData;
    selectData["table"] = getRangeCountQuery.at("table");
    auto& queryParam { selectData["query"] };
    const auto& querySelect { getRangeCountQuery["query"] };
    
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
    dbsync_select_rows(dbsync_handle, spJson.get(), { callbackDBSync, &sizeRange });

    return size;
}


std::string RSyncImplementation::getChecksums(const DBSYNC_HANDLE dbsync_handle, 
                                              const nlohmann::json& getRangeQuery,
                                              const std::string& begin,
                                              const std::string& end) 
{
    
    nlohmann::json selectData;
    selectData["table"] = getRangeQuery.at("table");
    auto& queryParam { selectData["query"] };
    const auto& querySelect { getRangeQuery["query"] };
    

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
    dbsync_select_rows(dbsync_handle, spJson.get(), { callbackDBSync, &calcChecksum });

    return Utils::asciiToHex(hash.hash());
}