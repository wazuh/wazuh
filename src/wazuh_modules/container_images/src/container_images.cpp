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
    m_impl = std::make_unique<containerimages::ContainerImagesImpl>(config);
    LoggingHelper::getInstance().log(LOG_DEBUG, "Module initialized.");
}

void ContainerImages::start()
{
    if (m_impl)
    {
        m_impl->run();
    }
}

void ContainerImages::stop()
{
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

    ContainerImages::instance().setLogFunction(
        [callback](const modules_log_level_t level, const std::string & log)
    {
        callback(level, log.c_str(), "container_images");
    });
}

void container_images_init(const unsigned int interval,
                           const bool scanOnStart,
                           const bool enabled,
                           const char** localPaths,
                           const unsigned int localPathsCount)
{
    try
    {
        containerimages::ContainerImagesConfig config;
        config.interval = interval;
        config.scanOnStart = scanOnStart;
        config.enabled = enabled;

        for (unsigned int i = 0; i < localPathsCount; ++i)
        {
            if (localPaths && localPaths[i])
            {
                config.localPaths.emplace_back(localPaths[i]);
            }
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
