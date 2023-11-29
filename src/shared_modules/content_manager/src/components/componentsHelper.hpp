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
#include <stdexcept>
#include <string>

namespace Utils
{
    /**
     * @brief Possible components' status.
     *
     */
    enum ComponentStatus
    {
        STATUS_OK,
        STATUS_FAIL
    };

    /**
     * @brief Pushes the state of the current component into the data field of the context.
     *
     * @param componentName Name of the component.
     * @param componentStatus Status to be pushed.
     * @param context Reference to the component context.
     */
    static void pushComponentStatus(const std::string& componentName,
                                    const ComponentStatus& componentStatus,
                                    UpdaterContext& context)
    {
        const auto getComponentStatusString {
            [](const ComponentStatus& status)
            {
                switch (status)
                {
                    case ComponentStatus::STATUS_OK: return "ok"; break;

                    case ComponentStatus::STATUS_FAIL: return "fail"; break;

                    default: throw std::runtime_error {"Unknown component status: " + std::to_string(status)}; break;
                }
            }};

        auto statusObject = nlohmann::json::object();
        statusObject["stage"] = componentName;
        statusObject["status"] = getComponentStatusString(componentStatus);

        context.data.at("stageStatus").push_back(statusObject);
    }
} // namespace Utils

#endif // _COMPONENTS_HELPER_HPP
