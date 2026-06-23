/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTAINER_IMAGES_IMPL_HPP
#define _CONTAINER_IMAGES_IMPL_HPP

#include "container_images_config.hpp"
#include "iimage_reader.hpp"

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>

namespace containerimages
{
    /// @brief Builds the reader for a single local source path.
    ///
    /// Single seam through which future source types are selected. At this stage it
    /// always returns the local on-disk reader.
    std::unique_ptr<IImageReader> makeReader(const std::string& path);

    /// @brief Orchestrates the module: owns the configuration and the scan loop.
    class ContainerImagesImpl final
    {
        public:
            /// @param config Module configuration.
            /// @param readerFactory Factory used to build a reader for a source path (overridable for tests).
            ContainerImagesImpl(ContainerImagesConfig config,
                                std::function<std::unique_ptr<IImageReader>(const std::string&)> readerFactory = makeReader);

            /// @brief Run the scan loop until stop() is called. Blocks the caller.
            void run();

            /// @brief Signal the scan loop to finish and wake it up.
            void stop();

            /// @brief Run a single discovery pass and return the image count.
            std::size_t scanOnce();

        private:
            ContainerImagesConfig m_config;
            std::function<std::unique_ptr<IImageReader>(const std::string&)> m_readerFactory;
            bool m_running {false};
            std::mutex m_mutex;
            std::condition_variable m_condition;
    };
} // namespace containerimages

#endif // _CONTAINER_IMAGES_IMPL_HPP
