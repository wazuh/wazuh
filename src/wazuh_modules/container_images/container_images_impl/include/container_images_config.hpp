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
    /// @brief The kinds of image source the configuration grammar accepts.
    ///
    /// The three entry types are fixed here so that adding a source later adds behaviour
    /// only: the configuration does not change again. Only Archive is implemented at this
    /// stage; the other two are accepted and reported as unimplemented.
    enum class ReferenceType
    {
        Registry,   ///< `<ref>`: an image in a remote registry.
        Archive,    ///< `<archive>`: a saved image archive or an OCI image layout on disk.
        EngineStore ///< `<local>`: an image in the local container engine store.
    };

    /// @brief One configured image source.
    struct ConfiguredReference
    {
        ReferenceType type {ReferenceType::Archive};
        std::string location; ///< Path or image reference, as written in the configuration.
    };

    /// @brief Configuration name of a reference type, also stored as the reference type of
    /// every inventoried row.
    inline std::string referenceTypeName(const ReferenceType type)
    {
        switch (type)
        {
            case ReferenceType::Registry: return "ref";
            case ReferenceType::Archive: return "archive";
            case ReferenceType::EngineStore: return "local";
            default: return "unknown";
        }
    }

    /// @brief Resolve a configuration entry name to its reference type.
    /// @return True when @p name is one of the accepted entry types.
    inline bool parseReferenceType(const std::string& name, ReferenceType& type)
    {
        if (name == "ref")
        {
            type = ReferenceType::Registry;
        }
        else if (name == "archive")
        {
            type = ReferenceType::Archive;
        }
        else if (name == "local")
        {
            type = ReferenceType::EngineStore;
        }
        else
        {
            return false;
        }

        return true;
    }

    /// @brief Internal configuration model for the module.
    struct ContainerImagesConfig
    {
        bool enabled {true};
        bool scanOnStart {true};
        unsigned int interval {3600};                   ///< Seconds between scans.
        std::vector<ConfiguredReference> references;    ///< The configured image sources.

        // Persistence.
        std::string dbPath {"queue/container_images/db/container_images.db"}; ///< Local inventory DB.
    };
} // namespace containerimages

#endif // _CONTAINER_IMAGES_CONFIG_HPP
