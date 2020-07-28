/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 21, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _ACTION_H
#define _ACTION_H
#include <json.hpp>
#include <mutex>
#include "dbsync.h"
#include "makeUnique.h"

namespace TestDeleters
{
    struct CJsonDeleter final
    {
        void operator()(char* json)
        {
            cJSON_free(json);
        }
        void operator()(cJSON* json)
        {
            cJSON_Delete(json);
        }
    };

    struct ResultDeleter final
    {
        void operator()(cJSON* json)
        {
            dbsync_free_result(&json);
        }
    };
};

struct IAction
{
    virtual void execute(std::unique_ptr<TestContext>& ctx, const nlohmann::json& value) = 0;

    virtual ~IAction() = default;
};

struct UpdateWithSnapshotAction final : public IAction
{
    void execute(std::unique_ptr<TestContext>& ctx, const nlohmann::json& value) override
    {
        const std::unique_ptr<cJSON, TestDeleters::CJsonDeleter> currentSnapshotPtr
        { 
            cJSON_Parse(value["body"].dump().c_str())
        };
        cJSON* snapshotLambda{ nullptr };
        if(0 == dbsync_update_with_snapshot(ctx->handle, currentSnapshotPtr.get(), &snapshotLambda))
        {
            // Create and flush snapshot diff data in files like: snapshot_<#idx>.json
            const std::unique_ptr<cJSON, TestDeleters::ResultDeleter> snapshotLambdaPtr(snapshotLambda);
            
            std::stringstream oFileName;
            oFileName << "action_" << ctx->currentId << ".json";
            const std::string outputFileName{ ctx->outputPath +"/"+oFileName.str() };

            std::ofstream outputFile{ outputFileName };
            const std::unique_ptr<char, TestDeleters::CJsonDeleter> snapshotDiff{ cJSON_Print(snapshotLambdaPtr.get()) };
            outputFile << snapshotDiff.get() << std::endl;
        }
    }
};

static void dummyCallback(ReturnTypeCallback, const cJSON*, void*)
{

}

static void txnCallback(ReturnTypeCallback type, const cJSON* json, void* user_data)
{
    if (user_data && json)
    {
        static std::mutex s_mutex;
        std::lock_guard<std::mutex> lock{ s_mutex };
        TestContext* ctx{ reinterpret_cast<TestContext*>(user_data) };
        std::stringstream oFileName;
        oFileName << "txn_" << reinterpret_cast<size_t>(ctx->txnContext) << ".json";
        const auto outputFileName{ ctx->outputPath + "/" + oFileName.str() };
        const std::unique_ptr<char, TestDeleters::CJsonDeleter> spJsonBytes{cJSON_PrintUnformatted(json)};
        const auto newJson{nlohmann::json::parse(spJsonBytes.get())};
        nlohmann::json jsonResult;
        jsonResult.push_back(newJson[0]);
        jsonResult.push_back({{"result", type}});

        std::ofstream outputFile{ outputFileName, std::ofstream::app};
        outputFile << jsonResult.dump() << std::endl;
    }
}

struct CreateTransactionAction final : public IAction
{
    void execute(std::unique_ptr<TestContext>& ctx, 
                 const nlohmann::json& value) override
    {
        const std::unique_ptr<cJSON, TestDeleters::CJsonDeleter> jsonTables
        { 
            cJSON_Parse(value["body"]["tables"].dump().c_str())
        };
        
        callback_data_t callbackData { txnCallback, ctx.get() };

        ctx->txnContext = dbsync_create_txn(ctx->handle,
                                     jsonTables.get(),
                                     0,
                                     100,
                                     callbackData);

        std::stringstream oFileName;
        oFileName << "action_" << ctx->currentId << ".json";
        const auto outputFileName{ ctx->outputPath + "/" + oFileName.str() };

        std::ofstream outputFile{ outputFileName };
        const nlohmann::json jsonResult = { {"txn_context", nullptr != ctx->txnContext } };
        outputFile << jsonResult.dump() << std::endl;
    }
};

struct CloseTransactionAction final : public IAction
{
    void execute(std::unique_ptr<TestContext>& ctx, 
                 const nlohmann::json& /*value*/) override
    {
        

        const auto retVal { dbsync_close_txn(ctx->txnContext)} ;

            std::stringstream oFileName;
            oFileName << "action_" << ctx->currentId << ".json";
            const auto outputFileName{ ctx->outputPath + "/" + oFileName.str() };

            std::ofstream outputFile{ outputFileName };
            const nlohmann::json jsonResult = { {"txn_context", retVal } };
            outputFile << jsonResult.dump() << std::endl;
    }
};

struct SetMaxRowsAction final : public IAction
{
    void execute(std::unique_ptr<TestContext>& ctx,
                 const nlohmann::json& value) override
    {
        const auto table{value["body"]["table"].get<std::string>()};
        const auto maxRows{value["body"]["max_rows"].get<unsigned int>()};
        const auto retVal
        {
            dbsync_set_table_max_rows(ctx->handle,
                                      table.c_str(),
                                      maxRows)
        };

        std::stringstream oFileName;
        oFileName << "action_" << ctx->currentId << ".json";
        const auto outputFileName{ ctx->outputPath + "/" + oFileName.str() };

        std::ofstream outputFile{ outputFileName };
        const nlohmann::json jsonResult = { {"dbsync_set_table_max_rows", retVal } };
        outputFile << jsonResult.dump() << std::endl;
    }
};

struct GetDeleteTxnCallbackLogger final 
{
    explicit GetDeleteTxnCallbackLogger(const std::string &fileName) 
    : m_fileName(fileName)
    {};
    std::string m_fileName;
    std::mutex m_mutex;

};

static void getDeleteTxnCallback(ReturnTypeCallback /*type*/,
                                 const cJSON* json,
                                 void* user_data)
{
    GetDeleteTxnCallbackLogger* loggerContext { reinterpret_cast<GetDeleteTxnCallbackLogger *>(user_data) };

    std::lock_guard<std::mutex> lock(loggerContext->m_mutex);
    std::ifstream inputFile{ loggerContext->m_fileName };
    nlohmann::json jsonResult {};
    if (inputFile.peek() != std::ifstream::traits_type::eof())
    {
        jsonResult = nlohmann::json::parse(inputFile);
    }
    const std::unique_ptr<char, TestDeleters::CJsonDeleter> spJsonBytes{cJSON_PrintUnformatted(json)};
    const auto& newJson { nlohmann::json::parse(spJsonBytes.get()) };
    jsonResult.push_back(newJson[0]);

    std::ofstream outputFile{ loggerContext->m_fileName };
    outputFile << jsonResult.dump() << std::endl;
};


struct GetDeletedRowsAction final : public IAction
{
    void execute(std::unique_ptr<TestContext>& ctx,
                 const nlohmann::json& /*value*/) override
    {
        std::stringstream oFileName;
        oFileName << "action_" << ctx->currentId << ".json";
        const auto& outputFileName{ ctx->outputPath + "/" + oFileName.str() };
        const auto& outputFileNameCallback{ ctx->outputPath + "/" + "callback." + oFileName.str() };

        const auto& loggerContext { std::make_unique<GetDeleteTxnCallbackLogger>(outputFileNameCallback) };
        callback_data_t callbackData { getDeleteTxnCallback, loggerContext.get() } ;
        
        const auto retVal
        {
            dbsync_get_deleted_rows(ctx->txnContext,
                                    callbackData)
        };
        
        std::ofstream outputFile{ outputFileName };
        const nlohmann::json& jsonResult { {"dbsync_get_deleted_rows", retVal } };
        outputFile << jsonResult.dump() << std::endl;
    }
};

struct SyncRowAction final : public IAction
{
    void execute(std::unique_ptr<TestContext>& ctx,
                 const nlohmann::json& value) override
    {
        const std::unique_ptr<cJSON, TestDeleters::CJsonDeleter> jsInput
        {
            cJSON_Parse(value["body"].dump().c_str())
        };

        callback_data_t callbackData { dummyCallback, nullptr };

        const auto retVal
        {
            dbsync_sync_row(ctx->handle,
                            jsInput.get(),
                            callbackData)
        };

        std::stringstream oFileName;
        oFileName << "action_" << ctx->currentId << ".json";
        const auto outputFileName{ ctx->outputPath + "/" + oFileName.str() };

        std::ofstream outputFile{ outputFileName };
        const nlohmann::json jsonResult = { {"dbsync_sync_row", retVal } };
        outputFile << jsonResult.dump() << std::endl;
    }
};

struct SyncTxnRowsAction final : public IAction
{
    void execute(std::unique_ptr<TestContext>& ctx,
                 const nlohmann::json& value) override
    {
        const std::unique_ptr<cJSON, TestDeleters::CJsonDeleter> jsInput
        {
            cJSON_Parse(value["body"].dump().c_str())
        };

        const auto retVal
        {
            dbsync_sync_txn_row(ctx->txnContext,
                                jsInput.get())
        };

        std::stringstream oFileName;
        oFileName << "action_" << ctx->currentId << ".json";
        const auto outputFileName{ ctx->outputPath + "/" + oFileName.str() };

        std::ofstream outputFile{ outputFileName };
        const nlohmann::json jsonResult = { {"dbsync_sync_txn_row", retVal } };
        outputFile << jsonResult.dump() << std::endl;
    }
};


#endif //_ACTION_H