/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "container_images.hpp"
#include "container_images.h"
#include "ci_logging_helper.hpp"

#include "dbsync.hpp"

#include <exception>
#include <string>

void ContainerImages::setLogFunction(const std::function<void(const modules_log_level_t, const std::string&)>& logFunction)
{
    LoggingHelper::setLogCallback([logFunction](const modules_log_level_t level, const char* log)
    {
        logFunction(level, log);
    });
}

void ContainerImages::init(const containerimages::ContainerImagesConfig& config)
{
    // DBSync routes its internal errors through this static logger. Initialize once,
    // before any DBSync instance is created.
    DBSync::initialize([](const std::string & message)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, message);
    });

    m_impl = std::make_unique<containerimages::ContainerImagesImpl>(config);
    LoggingHelper::getInstance().log(LOG_DEBUG, "Module initialized.");
}

void ContainerImages::start()
{
    if (m_impl && !m_stopRequested)
    {
        m_impl->run();
    }
}

void ContainerImages::stop()
{
    m_stopRequested = true;

    if (m_impl)
    {
        m_impl->stop();
    }
}

void ContainerImages::releaseResources()
{
    m_impl.reset();
}

void container_images_set_log_function(log_callback_t callback)
{
    if (!callback)
    {
        return;
    }

    try
    {
        ContainerImages::instance().setLogFunction(
            [callback](const modules_log_level_t level, const std::string & log)
        {
            callback(level, log.c_str(), "container_images");
        });
    }
    catch (const std::exception& ex)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, ex.what());
    }
}

namespace
{
    /// Registry options handed over before initialization.
    ///
    /// Held here rather than added to container_images_init()'s parameter list, which is
    /// already long, and set before it so the configuration is complete by the time the
    /// implementation is constructed.
    std::vector<containerimages::RegistryCredentials> g_registryAuth;
    std::string g_caBundle;
} // namespace

void container_images_set_registry_options(const char** registryHosts,
                                           const char** registryUserKeys,
                                           const char** registryPasskeyKeys,
                                           const unsigned int registryAuthCount,
                                           const char* caBundle)
{
    try
    {
        g_registryAuth.clear();
        g_caBundle = caBundle != nullptr ? caBundle : "";

        for (unsigned int i = 0; i < registryAuthCount; ++i)
        {
            if (registryHosts == nullptr || registryHosts[i] == nullptr)
            {
                continue;
            }

            containerimages::RegistryCredentials credentials;
            credentials.host = registryHosts[i];

            if (registryUserKeys != nullptr && registryUserKeys[i] != nullptr)
            {
                credentials.userKey = registryUserKeys[i];
            }

            if (registryPasskeyKeys != nullptr && registryPasskeyKeys[i] != nullptr)
            {
                credentials.passkeyKey = registryPasskeyKeys[i];
            }

            g_registryAuth.push_back(std::move(credentials));
        }
    }
    catch (const std::exception& ex)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, ex.what());
    }
}

void container_images_init(const unsigned int interval,
                           const bool scanOnStart,
                           const bool enabled,
                           const char** referenceTypes,
                           const char** referenceValues,
                           const unsigned int referencesCount)
{
    try
    {
        containerimages::ContainerImagesConfig config;
        config.interval = interval;
        config.scanOnStart = scanOnStart;
        config.enabled = enabled;
        config.registryAuth = g_registryAuth;
        config.caBundle = g_caBundle;

        for (unsigned int i = 0; i < referencesCount; ++i)
        {
            if (!referenceTypes || !referenceTypes[i] || !referenceValues || !referenceValues[i])
            {
                continue;
            }

            containerimages::ConfiguredReference reference;

            // The configuration parser already rejects the entry names it does not know,
            // so an unknown type here means the two sides disagree, and the reference is
            // dropped rather than guessed.
            if (!containerimages::parseReferenceType(referenceTypes[i], reference.type))
            {
                LoggingHelper::getInstance().log(LOG_WARNING,
                                                 std::string {"Unknown reference type '"} + referenceTypes[i] +
                                                 "', skipping it.");
                continue;
            }

            reference.location = referenceValues[i];
            config.references.push_back(std::move(reference));
        }

        ContainerImages::instance().init(config);
    }
    catch (const std::exception& ex)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, ex.what());
    }
}

void container_images_start()
{
    try
    {
        ContainerImages::instance().start();
    }
    catch (const std::exception& ex)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, ex.what());
    }
}

void container_images_stop()
{
    try
    {
        ContainerImages::instance().stop();
    }
    catch (const std::exception& ex)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, ex.what());
    }
}

void container_images_release_resources()
{
    try
    {
        ContainerImages::instance().releaseResources();
    }
    catch (const std::exception& ex)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, ex.what());
    }
}
