/*
 * Wazuh Content Manager
 * Copyright (C) 2015, Wazuh Inc.
 * Nov 29, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _COMPONENTS_HELPER_HPP
#define _COMPONENTS_HELPER_HPP

#include "json.hpp"
#include "updaterContext.hpp"
#include <map>
#include <stdexcept>
#include <string>

namespace Components
{
    /**
     * @brief Possible components' status.
     *
     */
    enum class Status
    {
        STATUS_OK,
        STATUS_FAIL
    };

    namespace Columns
    {
        static const std::string CURRENT_OFFSET {"current_offset"};             ///< Database column name for offsets.
        static const std::string DOWNLOADED_FILE_HASH {"downloaded_file_hash"}; ///< Database column name for hashes.
    }                                                                           // namespace Columns

    /**
     * @brief Pushes the state of the current component into the data field of the context.
     *
     * @param componentName Name of the component.
     * @param componentStatus Status to be pushed.
     * @param context Reference to the component context.
     */
    static void
    pushStatus(const std::string& componentName, const Components::Status& componentStatus, UpdaterContext& context)
    {
        if (componentName.empty())
        {
            throw std::runtime_error {"Can not push status with empty component name"};
        }

        // LCOV_EXCL_START
        const std::map<Components::Status, std::string> statusTags {{Components::Status::STATUS_OK, "ok"},
                                                                    {Components::Status::STATUS_FAIL, "fail"}};
        // LCOV_EXCL_STOP

        auto statusObject = nlohmann::json::object();
        statusObject["stage"] = componentName;
        statusObject["status"] = statusTags.at(componentStatus);

        context.data.at("stageStatus").push_back(statusObject);
    }
} // namespace Components

#endif // _COMPONENTS_HELPER_HPP
