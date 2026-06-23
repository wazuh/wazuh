/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTAINER_IMAGES_CONFIG_HPP
#define _CONTAINER_IMAGES_CONFIG_HPP

#include <string>
#include <vector>

namespace containerimages
{
    /// @brief Internal configuration model for the module.
    struct ContainerImagesConfig
    {
        bool enabled {true};
        bool scanOnStart {true};
        unsigned int interval {3600};        ///< Seconds between scans.
        std::vector<std::string> localPaths; ///< Paths of the configured local sources.
    };
} // namespace containerimages

#endif // _CONTAINER_IMAGES_CONFIG_HPP
