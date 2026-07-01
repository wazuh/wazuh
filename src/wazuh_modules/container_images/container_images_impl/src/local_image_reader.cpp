/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "local_image_reader.hpp"
#include "ci_logging_helper.hpp"

#include <filesystem>
#include <fstream>
#include <utility>

#include <json.hpp>

namespace
{
    const std::string SOURCE_TYPE {"local"};
    const std::string OCI_LAYOUT_MARKER {"oci-layout"};
    const std::string OCI_INDEX_FILE {"index.json"};
    const std::string BLOBS_DIR {"blobs"};

    // Markers used to recognize formats that are detected but not yet supported.
    const std::string DOCKER_ARCHIVE_MARKER {"manifest.json"};
    const std::string CONTAINERD_MARKER {"io.containerd.content.v1.content"};

    void logDebug(const std::string& message)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, message);
    }

    void logWarn(const std::string& message)
    {
        LoggingHelper::getInstance().log(LOG_WARNING, message);
    }

    /// @brief Recognized local layout formats.
    enum class LocalFormat
    {
        OciLayout,      ///< OCI image layout (supported).
        DockerArchive,  ///< `docker save` archive directory (not implemented yet).
        Containerd,     ///< containerd content store (not implemented yet).
        Unknown         ///< Could not be identified.
    };

    /// @brief Inspect a path and decide which local format it holds.
    LocalFormat detectFormat(const std::filesystem::path& path)
    {
        std::error_code errorCode;

        if (std::filesystem::exists(path / OCI_LAYOUT_MARKER, errorCode))
        {
            return LocalFormat::OciLayout;
        }

        if (std::filesystem::exists(path / CONTAINERD_MARKER, errorCode))
        {
            return LocalFormat::Containerd;
        }

        if (std::filesystem::exists(path / DOCKER_ARCHIVE_MARKER, errorCode))
        {
            return LocalFormat::DockerArchive;
        }

        return LocalFormat::Unknown;
    }

    /// @brief Human-readable name of a detected format, for logs.
    std::string formatName(LocalFormat format)
    {
        switch (format)
        {
            case LocalFormat::OciLayout: return "oci-layout";
            case LocalFormat::DockerArchive: return "docker-archive";
            case LocalFormat::Containerd: return "containerd";
            default: return "unknown";
        }
    }

    /// @brief Read and parse a JSON file, returning an empty object on failure.
    nlohmann::json readJsonFile(const std::filesystem::path& path)
    {
        std::ifstream stream(path);

        if (!stream.is_open())
        {
            logDebug("Could not open file: " + path.string());
            return nlohmann::json::object();
        }

        return nlohmann::json::parse(stream, nullptr, false);
    }

    /// @brief True if a digest component is safe to use as a path segment.
    ///
    /// The component is read from on-disk JSON that may be attacker-controlled, so
    /// anything that could escape the layout directory (path separators, parent
    /// references, empty) is rejected.
    bool isSafeDigestComponent(const std::string& component)
    {
        if (component.empty() || component == "." || component == "..")
        {
            return false;
        }

        return component.find('/') == std::string::npos &&
               component.find('\\') == std::string::npos;
    }

    /// @brief Resolve a digest ("sha256:abc...") to its blob path under the layout.
    /// Returns an empty path for malformed or unsafe digests.
    std::filesystem::path blobPath(const std::filesystem::path& layoutPath, const std::string& digest)
    {
        const auto separator = digest.find(':');

        if (separator == std::string::npos)
        {
            return {};
        }

        const auto algorithm = digest.substr(0, separator);
        const auto value = digest.substr(separator + 1);

        if (!isSafeDigestComponent(algorithm) || !isSafeDigestComponent(value))
        {
            logDebug("Rejected unsafe digest: " + digest);
            return {};
        }

        return layoutPath / BLOBS_DIR / algorithm / value;
    }

    /// @brief Fill platform metadata from a parsed configuration blob.
    void applyConfigMetadata(const nlohmann::json& config, containerimages::ImageReferenceRecord& record)
    {
        record.os = config.value("os", "");
        record.architecture = config.value("architecture", "");
        record.variant = config.value("variant", "");
        record.osVersion = config.value("os.version", "");
    }
} // namespace

namespace containerimages
{
    LocalImageReader::LocalImageReader(std::string layoutPath)
        : m_layoutPath {std::move(layoutPath)}
    {
    }

    std::string LocalImageReader::sourceType() const
    {
        return SOURCE_TYPE;
    }

    std::vector<ImageReferenceRecord> LocalImageReader::discover()
    {
        std::vector<ImageReferenceRecord> records;

        std::error_code errorCode;
        const std::filesystem::path path {m_layoutPath};

        if (m_layoutPath.empty() || !std::filesystem::is_directory(path, errorCode))
        {
            logWarn("Local path is not a directory: " + m_layoutPath);
            return records;
        }

        const auto format = detectFormat(path);

        if (format != LocalFormat::OciLayout)
        {
            logWarn("NOT IMPLEMENTED: local format '" + formatName(format) + "' at '" + m_layoutPath +
                    "' is not supported yet, skipping.");
            return records;
        }

        return readOciLayout(path);
    }

    std::vector<ImageReferenceRecord> LocalImageReader::readOciLayout(const std::filesystem::path& layoutPath)
    {
        std::vector<ImageReferenceRecord> records;

        const auto index = readJsonFile(layoutPath / OCI_INDEX_FILE);

        if (!index.contains("manifests") || !index["manifests"].is_array())
        {
            logDebug("Index has no manifests at: " + layoutPath.string());
            return records;
        }

        for (const auto& manifestRef : index["manifests"])
        {
            const auto manifestDigest = manifestRef.value("digest", "");

            if (manifestDigest.empty())
            {
                continue;
            }

            const auto manifest = readJsonFile(blobPath(layoutPath, manifestDigest));
            const auto configDigest = manifest.contains("config") ? manifest["config"].value("digest", "") : "";

            if (configDigest.empty())
            {
                logDebug("Manifest without config digest: " + manifestDigest);
                continue;
            }

            ImageReferenceRecord record;
            record.configDigest = configDigest;
            record.manifestDigest = manifestDigest;

            applyConfigMetadata(readJsonFile(blobPath(layoutPath, configDigest)), record);

            if (manifestRef.contains("annotations") && manifestRef["annotations"].is_object())
            {
                record.tag = manifestRef["annotations"].value("org.opencontainers.image.ref.name", "");
            }

            record.source = {SOURCE_TYPE, layoutPath.string()};
            records.push_back(std::move(record));
        }

        return records;
    }
} // namespace containerimages
