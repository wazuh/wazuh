/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "docker_image_source.hpp"

#include "oci_metadata.hpp"

#include <filesystem>
#include <utility>

namespace
{
    // Only the path is used: the request goes through the socket, whatever the host says.
    const std::string ENGINE_URL {"http://localhost"};

    std::vector<std::string> stringsOf(const nlohmann::json& entry, const std::string& key)
    {
        std::vector<std::string> values;

        for (const auto& value : containerimages::oci::arrayField(entry, key))
        {
            if (value.is_string())
            {
                values.push_back(value.get<std::string>());
            }
        }

        return values;
    }
} // namespace

namespace containerimages
{
    DockerImageSource::DockerImageSource(const std::string& socketPath,
                                         const ContainerImagesConfig& config,
                                         const std::atomic<bool>* stopRequested)
        : m_socketPath {socketPath}
        , m_transportConfig {}
        , m_stopRequested {stopRequested}
    {
        m_transportConfig.unixSocketPath = socketPath;
        m_transportConfig.connectTimeoutMs = config.limits.connectTimeoutMs;
        m_transportConfig.requestTimeoutMs = config.limits.requestTimeoutMs;
        m_transportConfig.blobIdleTimeoutMs = config.limits.blobIdleTimeoutMs;
        m_transport = std::make_unique<CurlRegistryTransport>(m_transportConfig);
    }

    DockerImageSource::DockerImageSource(std::string socketPath,
                                         std::unique_ptr<IRegistryTransport> transport,
                                         BlobStreamFactory exportStream,
                                         TransportConfig transportConfig,
                                         const std::atomic<bool>* stopRequested)
        : m_socketPath {std::move(socketPath)}
        , m_transport {std::move(transport)}
        , m_exportStream {std::move(exportStream)}
        , m_transportConfig {std::move(transportConfig)}
        , m_stopRequested {stopRequested}
    {
    }

    bool DockerImageSource::socketUsable(std::string& error) const
    {
        std::error_code errorCode;
        const auto status {std::filesystem::status(m_socketPath, errorCode)};

        if (errorCode == std::errc::permission_denied)
        {
            error = "permission denied on the Docker socket '" + m_socketPath + "', which the agent cannot reach";
            return false;
        }

        if (errorCode && errorCode != std::errc::no_such_file_or_directory)
        {
            error = "the Docker socket '" + m_socketPath + "' cannot be checked: " + errorCode.message();
            return false;
        }

        if (errorCode || status.type() == std::filesystem::file_type::not_found)
        {
            error = "the Docker socket '" + m_socketPath + "' does not exist, so the engine is not running or is configured elsewhere";
            return false;
        }

        if (status.type() != std::filesystem::file_type::socket)
        {
            error = "'" + m_socketPath + "' is not a Unix socket";
            return false;
        }

        return true;
    }

    bool DockerImageSource::listImages(std::vector<EngineImage>& images, std::string& error)
    {
        images.clear();

        if (!socketUsable(error))
        {
            return false;
        }

        HttpResponse response;

        if (!m_transport->get(ENGINE_URL + "/images/json", {"Accept: application/json"}, response, error))
        {
            error = "the list of images could not be requested: " + error;
            return false;
        }

        if (response.status != 200)
        {
            error = "the engine answered " + std::to_string(response.status) + " to the list of images";
            return false;
        }

        const auto document = nlohmann::json::parse(response.body, nullptr, false);

        if (!document.is_array())
        {
            error = "the engine's list of images is not a JSON list";
            return false;
        }

        for (const auto& entry : document)
        {
            if (!entry.is_object())
            {
                continue;
            }

            EngineImage image;
            image.id = oci::stringField(entry, "Id");

            if (image.id.empty())
            {
                continue;
            }

            image.repoTags = stringsOf(entry, "RepoTags");
            image.repoDigests = stringsOf(entry, "RepoDigests");

            const auto size {entry.find("Size")};

            if (size != entry.end() && size->is_number_unsigned())
            {
                image.size = size->get<std::uint64_t>();
            }

            images.push_back(std::move(image));
        }

        return true;
    }

    std::unique_ptr<IBlobStream> DockerImageSource::exportImage(const std::string& id,
                                                                const std::uint64_t maxBytes,
                                                                std::string& error)
    {
        // The id is put into a request path, so it has to be a digest and nothing else.
        if (!oci::isHexDigest(id))
        {
            error = "'" + id.substr(0, 80) + "' is not an image id";
            return nullptr;
        }

        if (!socketUsable(error))
        {
            return nullptr;
        }

        const auto url {ENGINE_URL + "/images/" + id + "/get"};
        const std::vector<std::string> headers {"Accept: application/x-tar"};

        if (m_exportStream)
        {
            return m_exportStream(m_transportConfig, url, headers, maxBytes, m_stopRequested);
        }

        return std::make_unique<RegistryByteStream>(m_transportConfig, url, headers, maxBytes, m_stopRequested);
    }
} // namespace containerimages
