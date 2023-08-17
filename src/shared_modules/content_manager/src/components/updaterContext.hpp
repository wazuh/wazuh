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

#include "iRouterProvider.hpp"
#include "routerProvider.hpp"
#include <external/nlohmann/json.hpp>
#include <filesystem>
#include <vector>

/**
 * @brief Object handled on every step of the updater chain.
 *
 */
struct UpdaterBaseContext
{
    /**
     * @brief Configurations for the current run.
     *
     */
    nlohmann::json configData;

    /**
     * @brief Channel where the data will be published.
     *
     */
    std::shared_ptr<IRouterProvider> spChannel;

    /**
     * @brief Path to the output folder where the data will be stored.
     *
     */
    std::filesystem::path outputFolder;

    /**
     * @brief For testing purposes. Delete it.
     */
    uint8_t download {1};      ///< download
    uint8_t decompress {0};    ///< decompress
    uint8_t publish {0};       ///< publish
    uint8_t updateVersion {0}; ///< updateVersion
    uint8_t clean {0};         ///< clean
};

/**
 * @brief Object created and handled on every execution of the updater chain.
 *
 */
struct UpdaterContext final : private UpdaterBaseContext
{
    /**
     * @brief Pointer to the Updater context.
     */
    std::shared_ptr<UpdaterBaseContext> spUpdaterBaseContext;

    /**
     * @brief Data to be published.
     *
     */
    std::vector<char> data;
};

#endif // _UPDATER_CONTEXT_HPP
