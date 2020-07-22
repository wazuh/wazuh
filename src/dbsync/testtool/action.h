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
#include "dbsync.h"

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


struct CreateTransactionAction final : public IAction
{
    void execute(std::unique_ptr<TestContext>& ctx, 
                 const nlohmann::json& value) override
    {
        const std::unique_ptr<cJSON, TestDeleters::CJsonDeleter> jsonTables
        { 
            cJSON_Parse(value["body"]["tables"].dump().c_str())
        };

        ctx->txnContext = dbsync_create_txn(ctx->handle,
                                     jsonTables.get(),
                                     0,
                                     0,
                                     (result_callback_t)0x1);

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
        

        const auto retVal { dbsync_close_txn(ctx->handle,
                                             ctx->txnContext)} ;

            std::stringstream oFileName;
            oFileName << "action_" << ctx->currentId << ".json";
            const auto outputFileName{ ctx->outputPath + "/" + oFileName.str() };

            std::ofstream outputFile{ outputFileName };
            const nlohmann::json jsonResult = { {"txn_context", retVal } };
            outputFile << jsonResult.dump() << std::endl;
    }
};

#endif //_ACTION_H