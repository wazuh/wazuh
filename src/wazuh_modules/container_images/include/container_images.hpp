/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTAINER_IMAGES_HPP
#define _CONTAINER_IMAGES_HPP

#include "container_images_config.hpp"
#include "container_images_impl.hpp"
#include "logging_helper.h"

#include <functional>
#include <memory>
#include <string>

#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

/// @brief Module facade: owns the lifecycle and bridges the C interface to the
/// implementation.
class EXPORTED ContainerImages final
{
    public:
        static ContainerImages& instance()
        {
            static ContainerImages s_instance;
            return s_instance;
        }

        void setLogFunction(const std::function<void(const modules_log_level_t, const std::string&)>& logFunction);
        void init(const containerimages::ContainerImagesConfig& config);
        void start();
        void stop();
        void releaseResources();

    private:
        ContainerImages() = default;
        ~ContainerImages() = default;
        ContainerImages(const ContainerImages&) = delete;
        ContainerImages& operator=(const ContainerImages&) = delete;

        std::unique_ptr<containerimages::ContainerImagesImpl> m_impl;
};

#endif // _CONTAINER_IMAGES_HPP
