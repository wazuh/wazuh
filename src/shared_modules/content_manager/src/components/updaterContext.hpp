/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 06, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _UPDATER_CONTEXT_HPP
#define _UPDATER_CONTEXT_HPP

#include "conditionSync.hpp"
#include "iRouterProvider.hpp"
#include "json.hpp"
#include "utils/rocksDBWrapper.hpp"
#include <external/nlohmann/json.hpp>
#include <filesystem>
#include <memory>
#include <string>
#include <utility>

constexpr auto DOWNLOAD_FOLDER = "downloads";
constexpr auto CONTENTS_FOLDER = "contents";

/**
 * @brief Object handled on every step of the updater chain.
 *
 */
struct UpdaterBaseContext
{
    /**
     * @brief Name of the topic where the data will be published.
     *
     */
    std::string topicName;

    /**
     * @brief Configurations for the current run.
     *
     */
    nlohmann::json configData;

    /**
     * @brief HTTP User-Agent header value.
     *
     */
    std::string httpUserAgent;

    /**
     * @brief Channel where the data will be published.
     *
     */
    std::shared_ptr<IRouterProvider> spChannel;

    /**
     * @brief Pointer to the RocksDB instance.
     *
     */
    std::unique_ptr<Utils::RocksDBWrapper> spRocksDB {};

    /**
     * @brief Path to the output folder where the data will be stored.
     *
     */
    std::filesystem::path outputFolder;

    /**
     * @brief Path to the folder where the compressed content will be downloaded.
     *
     */
    std::filesystem::path downloadsFolder;

    /**
     * @brief Path to the folder where the content will be decompressed or the raw content will be stored.
     *
     */
    std::filesystem::path contentsFolder;

    /**
     * @brief Hash of the downloaded file. Used to avoid redundant publications.
     *
     */
    std::string downloadedFileHash;

    /**
     * @brief Variable to control the graceful shutdown of the orchestration.
     *
     */
    std::shared_ptr<ConditionSync> spStopCondition;

    /**
     * @brief Struct constructor.
     *
     * @param spStopCondition Pointer to a stop condition wrapper.
     */
    explicit UpdaterBaseContext(std::shared_ptr<ConditionSync> spStopCondition)
        : spStopCondition(std::move(spStopCondition))
    {
    }
};

/**
 * @brief Object created and handled on every execution of the updater chain.
 *
 */
struct UpdaterContext
{
    /**
     * @brief Pointer to the Updater context.
     */
    std::shared_ptr<UpdaterBaseContext> spUpdaterBaseContext;

    /**
     * @brief Data to be published.
     *
     * @details JSON file structure:
     *  {
     *      "type": "raw",
     *      "offset": 0,
     *      "paths":
     *      [
     *          "/tmp/outputFolder/file1.json",
     *          "/tmp/outputFolder/file2.json"
     *      ],
     *      "stageStatus":
     *      [
     *          {
     *              "stage": "download",
     *              "status": "ok"
     *          }
     *      ]
     *  }
     *
     */
    nlohmann::json data = R"({ "type": "raw", "offset": 0, "paths": [], "stageStatus": [] })"_json;

    /**
     * @brief Represents the offset processed in the current run.
     *
     */
    int currentOffset {0};
};

#endif // _UPDATER_CONTEXT_HPP
