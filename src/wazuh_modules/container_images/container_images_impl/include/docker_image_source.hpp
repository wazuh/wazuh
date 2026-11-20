/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DOCKER_IMAGE_SOURCE_HPP
#define _DOCKER_IMAGE_SOURCE_HPP

#include "container_images_config.hpp"
#include "engine_image_source.hpp"
#include "registry_transport.hpp"

#include <atomic>
#include <memory>
#include <string>

namespace containerimages
{
    /// @brief Name `<local>` gives the Docker engine, and the engine part of its images' keys.
    constexpr auto DOCKER_ENGINE {"docker"};

    /// @brief Documented socket of the Docker engine, used when the configuration names none.
    constexpr auto DEFAULT_DOCKER_SOCKET {"/var/run/docker.sock"};

    /// @brief The Docker Engine API over a Unix socket: `GET /images/json` and `GET /images/{id}/get`.
    ///
    /// Runs on the module's own libcurl transport, which learned to talk to a socket instead of
    /// a registry, so it adds no dependency to any package.
    class DockerImageSource final : public IEngineImageSource
    {
        public:
            /// @param socketPath    Unix socket of the engine.
            /// @param config        Timeouts and size limits, the same as for a registry.
            /// @param stopRequested Set when the module is asked to stop. Not owned. May be null.
            DockerImageSource(const std::string& socketPath,
                              const ContainerImagesConfig& config,
                              const std::atomic<bool>* stopRequested = nullptr);

            /// @brief Replace the transport and the export stream, for tests.
            DockerImageSource(std::string socketPath,
                              std::unique_ptr<IRegistryTransport> transport,
                              BlobStreamFactory exportStream,
                              TransportConfig transportConfig,
                              const std::atomic<bool>* stopRequested = nullptr);

            bool listImages(std::vector<EngineImage>& images, std::string& error) override;

            std::unique_ptr<IBlobStream> exportImage(const std::string& id,
                                                     std::uint64_t maxBytes,
                                                     std::string& error) override;

        private:
            /// @brief True when the socket path exists and is a socket, with the reason when not.
            bool socketUsable(std::string& error) const;

            std::string m_socketPath;
            std::unique_ptr<IRegistryTransport> m_transport;
            BlobStreamFactory m_exportStream;
            TransportConfig m_transportConfig;
            const std::atomic<bool>* m_stopRequested;
    };
} // namespace containerimages

#endif // _DOCKER_IMAGE_SOURCE_HPP
