/*
 * Wazuh Syscheck - Test tool
 * Copyright (C) 2015, Wazuh Inc.
 * January 21, 2022.
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
#include <iostream>
#include <sstream>
#include <fstream>
#include "commonDefs.h"
#include "dbsync.hpp"
#include "testContext.h"
#include "db.hpp"


struct IAction
{
    virtual void execute(std::unique_ptr<TestContext>& ctx, const nlohmann::json& value) = 0;

    virtual ~IAction() = default;
};

struct RemoveFileAction final : public IAction
{
    void execute(std::unique_ptr<TestContext>& ctx, const nlohmann::json& value) override
    {
        auto retVal = false;
        try
        {
            DB::instance().removeFile(value.at("file_path").get_ref<const std::string&>());
            retVal = true;
        }
        catch (const std::exception &e)
        {
            std::cout << "Error removing file: "
                << value.at("file_path").get_ref<const std::string&>() << std::endl;
        }

        std::stringstream oFileName;
        oFileName << "action_" << ctx->currentId << ".json";
        const auto outputFileName{ ctx->outputPath + "/" + oFileName.str() };

        std::ofstream outputFile{ outputFileName };
        const nlohmann::json jsonResult = {
                { "result", retVal },
                { "action", "RemoveFile" }
            };
        outputFile << jsonResult.dump() << std::endl;
    }
};

struct GetFileAction final : public IAction
{
    void execute(std::unique_ptr<TestContext>& ctx, const nlohmann::json& value) override
    {
        auto retVal = false;
        nlohmann::json jsonReturn;
        try
        {
            DB::instance().getFile(value.at("file_path").get_ref<const std::string&>(),
                [&jsonReturn](const nlohmann::json& file) {
                    jsonReturn = file;
                });
            retVal = true;
        }
        catch (const std::exception &e)
        {
            std::cout << "Error getting file: "
                << value.at("file_path").get_ref<const std::string&>() << std::endl;
        }
        std::stringstream oFileName;
        oFileName << "action_" << ctx->currentId << ".json";
        const auto outputFileName{ ctx->outputPath + "/" + oFileName.str() };

        std::ofstream outputFile{ outputFileName };
        const nlohmann::json jsonResult = {
                { "result", retVal },
                { "value", jsonReturn },
                { "action", "GetFile" }
            };
        outputFile << jsonResult.dump() << std::endl;
    }
};

struct CountEntriesAction final : public IAction
{
    void execute(std::unique_ptr<TestContext>& ctx, const nlohmann::json& value) override
    {
        auto retVal = false;
        int count = 0;
        try
        {
            const auto filterType
            {
                static_cast<COUNT_SELECT_TYPE>(value.at("filter_type").get<int32_t>())
            };

            count = DB::instance().countEntries(value.at("table").get_ref<const std::string&>(), filterType);
            retVal = true;
        }
        catch (const std::exception &e)
        {
            std::cout << "Error counting entries: "
                << value.at("filter_type").get<int32_t>() << ", " << e.what() << std::endl;
        }
        std::stringstream oFileName;
        oFileName << "action_" << ctx->currentId << ".json";
        const auto outputFileName{ ctx->outputPath + "/" + oFileName.str() };

        std::ofstream outputFile{ outputFileName };
        const nlohmann::json jsonResult = {
                {"result", retVal },
                {"value", count},
                {"action", "CountEntries"}
            };
        outputFile << jsonResult.dump() << std::endl;
    }
};

struct UpdateFileAction final : public IAction
{
    void execute(std::unique_ptr<TestContext>& ctx, const nlohmann::json& value) override
    {
        auto retVal { false };
        nlohmann::json jsonEvent;

        directory_t configuration = {};
        configuration.options = -1;

        event_data_t evt_data = {};
        evt_data.report_event = true;
        evt_data.mode = FIM_REALTIME;
        evt_data.w_evt = NULL;

        callback_ctx cb_ctx = {};
        cb_ctx.event = &evt_data;
        cb_ctx.config = &configuration;

        try
        {
            DB::instance().updateFile(value, &cb_ctx,
            [&jsonEvent](const nlohmann::json data) {
                jsonEvent.push_back(data);
            });
            retVal = true;
        }
        catch (const std::exception &e)
        {
            std::cout << "Error updating file: "
                << value.at("data").get_ref<const std::string&>() << std::endl;
        }
        std::stringstream oFileName;
        oFileName << "action_" << ctx->currentId << ".json";
        const auto outputFileName{ ctx->outputPath + "/" + oFileName.str() };

        std::ofstream outputFile{ outputFileName };
        const nlohmann::json jsonResult = {
                {"result", retVal },
                {"jsonEvent", jsonEvent },
                {"action", "UpdateFile" }
            };
        outputFile << jsonResult.dump() << std::endl;
    }
};

struct SearchFileAction final : public IAction
{
    void execute(std::unique_ptr<TestContext>& ctx, const nlohmann::json& value) override
    {
        auto retVal = false;
        nlohmann::json jsonReturn;
        try
        {
            const auto searchType
            {
                static_cast<FILE_SEARCH_TYPE>(value.at("search_type").get<int32_t>())
            };
            DB::instance().searchFile(
                std::make_tuple(searchType,
                    value.at("search_value_path").get_ref<const std::string&>(),
                    value.at("search_value_inode").get_ref<const std::string&>(),
                    value.at("search_value_dev").get_ref<const std::string&>()),
                [&jsonReturn](const nlohmann::json& data) {
                    jsonReturn.push_back(data);
                });
            retVal = true;
        }
        catch (const std::exception &e)
        {
            std::cout << "Error searching files: "
                << value["file"].get_ref<const std::string&>() << std::endl;
        }
        std::stringstream oFileName;
        oFileName << "action_" << ctx->currentId << ".json";
        const auto outputFileName{ ctx->outputPath + "/" + oFileName.str() };

        std::ofstream outputFile{ outputFileName };
        const nlohmann::json jsonResult = {
                {"result", retVal },
                {"value", jsonReturn },
                {"action", "SearchFile" }
            };
        outputFile << jsonResult.dump() << std::endl;
    }
};

struct RunIntegrityAction final : public IAction
{
    void execute(std::unique_ptr<TestContext>& ctx, const nlohmann::json& /*value*/) override
    {
        auto retVal = false;
        try
        {
            DB::instance().runIntegrity();
            retVal = true;
        }
        catch (const std::exception &e)
        {
            std::cout << "Error running integrity: " << e.what() << std::endl;
        }
        std::stringstream oFileName;
        oFileName << "action_" << ctx->currentId << ".json";
        const auto outputFileName{ ctx->outputPath + "/" + oFileName.str() };

        std::ofstream outputFile{ outputFileName };
        const nlohmann::json jsonResult = {
                {"result", retVal },
                {"action", "RunIntegrity" }
            };
        outputFile << jsonResult.dump() << std::endl;
    }
};

struct PushMessageAction final : public IAction
{
    void execute(std::unique_ptr<TestContext>& ctx, const nlohmann::json& value) override
    {
        auto retVal = false;
        try
        {
            const auto message = value.at("message").get_ref<const std::string&>();
            DB::instance().pushMessage(message);
            retVal = true;
        }
        catch (const std::exception &e)
        {
            std::cout << "Error pushing message: " << e.what() << std::endl;
        }
        std::stringstream oFileName;
        oFileName << "action_" << ctx->currentId << ".json";
        const auto outputFileName{ ctx->outputPath + "/" + oFileName.str() };

        std::ofstream outputFile{ outputFileName };
        const nlohmann::json jsonResult = {
                {"result", retVal },
                {"action", "PushMessage" }
            };
        outputFile << jsonResult.dump() << std::endl;
    }
};

struct StartTransactionAction final : public IAction
{
    void execute(std::unique_ptr<TestContext>& ctx, const nlohmann::json& value) override
    {
        auto retVal = false;
        try
        {
            ctx->handle = DB::instance().DBSyncHandle();
            const auto table = value.at("table");
            const auto threadNumber { value.at("thread_number").get<int32_t>() };
            const auto queueSize { value.at("queue_size").get<int32_t>() };

            auto txnCallback = [&ctx](ReturnTypeCallback type, const nlohmann::json & json)
            {
                std::lock_guard<std::mutex> lock{ ctx->txn_callback_mutex };

                const auto outputFileName{ ctx->outputPath + "/txn_ops.json" };
                nlohmann::json jsonResult {};

                std::ifstream inputFile{ outputFileName };

                if (inputFile.good() && inputFile.peek() != std::ifstream::traits_type::eof())
                {
                    jsonResult = nlohmann::json::parse(inputFile);
                }

                jsonResult["data"].push_back( {
                        { "Operation type", RETURN_TYPE_OPERATION.at(type) },
                        { "value", json },
                        { "action", "SyncTxnRows" }
                    } );

                std::ofstream outputFile{ outputFileName };
                outputFile << jsonResult.dump(4) << std::endl;
            };
            ctx->txn.reset();
            ctx->txn = std::make_unique<DBSyncTxn>(ctx->handle,
                                                   table,
                                                   threadNumber,
                                                   queueSize,
                                                   txnCallback);

            retVal = true;
        }
        catch (const std::exception &e)
        {
            std::cout << "Error starting transaction: " << e.what() << std::endl;
        }
        std::stringstream oFileName;
        oFileName << "action_" << ctx->currentId << ".json";
        const auto outputFileName{ ctx->outputPath + "/" + oFileName.str() };

        std::ofstream outputFile{ outputFileName };
        const nlohmann::json jsonResult = {
                {"result", retVal },
                {"action", "StartTransaction" }
            };
        outputFile << jsonResult.dump() << std::endl;
    }
};

struct SyncTxnRowsAction final : public IAction
{
    void execute(std::unique_ptr<TestContext>& ctx, const nlohmann::json& value) override
    {
        auto retVal { false };

        try
        {
            ctx->txn->syncTxnRow(value);
            retVal = true;
        }
        catch (const std::exception& e)
        {
            std::cout << "Error in SyncTxnRow: " << e.what() << std::endl;
        }

        std::stringstream oFileName;
        oFileName << "action_" << ctx->currentId << ".json";
        const auto outputFileName{ ctx->outputPath + "/" + oFileName.str() };

        std::ofstream outputFile{ outputFileName };
        const nlohmann::json jsonResult = {
                {"result", retVal },
                {"action", "SyncTxnRows" }
            };

        outputFile << jsonResult.dump() << std::endl;
    }
};

struct GetDeletedRowsAction final : public IAction
{
    void execute(std::unique_ptr<TestContext>& ctx, const nlohmann::json& /*value*/) override
    {
        const auto txnOutputFileName{ ctx->outputPath + "/txn_ops.json" };
        auto callbackDelete
        {
            [txnOutputFileName, &ctx](ReturnTypeCallback type, const nlohmann::json & json)
            {
                std::lock_guard<std::mutex> lock(ctx->txn_callback_mutex);
                std::ifstream inputFile{ txnOutputFileName };

                nlohmann::json jsonResult {};

                if (inputFile.good() && inputFile.peek() != std::ifstream::traits_type::eof())
                {
                    jsonResult = nlohmann::json::parse(inputFile);
                }

                jsonResult["data"].push_back( {
                    {"Operation type", RETURN_TYPE_OPERATION.at(type) },
                    {"value", json },
                    {"action", "GetDeletedRows" }
                    } );

                std::ofstream outputFile{ txnOutputFileName };
                outputFile << jsonResult.dump() << std::endl;
            }
        };

        auto retVal { false };
        try
        {
            ctx->txn->getDeletedRows(callbackDelete);
            retVal = true;
        }
        catch (const std::exception& ex)
        {
            std::cerr << "Error in GetDeletedRows: " << ex.what() << std::endl;
        }

        std::stringstream oFileName;
        oFileName << "action_" << ctx->currentId << ".json";
        const auto& outputFileName{ ctx->outputPath + "/" + oFileName.str() };
        std::ofstream outputFile{ outputFileName };
        const nlohmann::json& jsonResult {
                {"result", retVal },
                {"action", "GetDeletedRows" }
            };
        outputFile << jsonResult.dump() << std::endl;
    }
};


#endif //_ACTION_H
