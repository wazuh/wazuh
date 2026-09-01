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

#include <algorithm>
#include <cstdint>
#include <exception>
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

    // Largest file the reader will parse. An OCI index or configuration blob is a few
    // kilobytes, so anything past this ceiling is not something this module should read
    // into memory.
    constexpr std::uintmax_t MAX_JSON_FILE_SIZE {16 * 1024 * 1024};

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
    ///
    /// The file type is checked before opening: the path is built from on-disk data and
    /// opening a FIFO with no writer would block the module thread indefinitely, past
    /// the point where a stop can reach it.
    nlohmann::json readJsonFile(const std::filesystem::path& path)
    {
        std::error_code errorCode;

        if (!std::filesystem::exists(path, errorCode))
        {
            logDebug("File does not exist: " + path.string());
            return nlohmann::json::object();
        }

        if (!std::filesystem::is_regular_file(path, errorCode))
        {
            logWarn("Not a regular file, skipping: " + path.string());
            return nlohmann::json::object();
        }

        const auto size = std::filesystem::file_size(path, errorCode);

        if (errorCode)
        {
            logWarn("Could not get the size of file: " + path.string());
            return nlohmann::json::object();
        }

        if (size > MAX_JSON_FILE_SIZE)
        {
            logWarn("File is larger than the " + std::to_string(MAX_JSON_FILE_SIZE) + " byte limit, skipping: " +
                    path.string());
            return nlohmann::json::object();
        }

        std::ifstream stream(path);

        if (!stream.is_open())
        {
            logDebug("Could not open file: " + path.string());
            return nlohmann::json::object();
        }

        // Non-throwing parse: a discarded value is returned on malformed input, and it is
        // not an object, so it would fail every accessor below.
        auto content = nlohmann::json::parse(stream, nullptr, false);

        if (!content.is_object())
        {
            logWarn("Could not parse a JSON object from file: " + path.string());
            return nlohmann::json::object();
        }

        return content;
    }

    /// @brief Read a string field, or an empty string when the node is not an object, the
    /// field is missing, or the field is not a string.
    ///
    /// Every field below comes from on-disk JSON that may be attacker-influenced, so no
    /// accessor may assume a type: nlohmann::json::value() throws on both counts.
    std::string stringField(const nlohmann::json& node, const std::string& key)
    {
        if (!node.is_object())
        {
            return {};
        }

        const auto field = node.find(key);

        return (field != node.end() && field->is_string()) ? field->get<std::string>() : std::string {};
    }

    /// @brief True if a digest algorithm matches the OCI character set `[a-z0-9]+`.
    bool isSafeDigestAlgorithm(const std::string& algorithm)
    {
        return !algorithm.empty() && std::all_of(algorithm.begin(), algorithm.end(), [](const char character)
        {
            return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9');
        });
    }

    /// @brief True if a digest encoded part matches the OCI character set `[a-zA-Z0-9=_-]+`.
    bool isSafeDigestEncoded(const std::string& encoded)
    {
        return !encoded.empty() && std::all_of(encoded.begin(), encoded.end(), [](const char character)
        {
            return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
                   (character >= '0' && character <= '9') || character == '=' || character == '_' || character == '-';
        });
    }

    /// @brief Resolve a digest ("sha256:abc...") to its blob path under the layout.
    /// Returns an empty path for malformed or unsafe digests.
    ///
    /// Both components are whitelisted rather than filtered for known-bad characters: a
    /// blacklist still lets through things such as a Windows drive-relative "C:foo",
    /// which operator/ would use to replace the layout path entirely.
    std::filesystem::path blobPath(const std::filesystem::path& layoutPath, const std::string& digest)
    {
        const auto separator = digest.find(':');

        if (separator == std::string::npos)
        {
            return {};
        }

        const auto algorithm = digest.substr(0, separator);
        const auto value = digest.substr(separator + 1);

        if (!isSafeDigestAlgorithm(algorithm) || !isSafeDigestEncoded(value))
        {
            logDebug("Rejected unsafe digest: " + digest);
            return {};
        }

        return layoutPath / BLOBS_DIR / algorithm / value;
    }

    /// @brief Fill platform metadata from a parsed configuration blob.
    void applyConfigMetadata(const nlohmann::json& config, containerimages::ImageReferenceRecord& record)
    {
        record.os = stringField(config, "os");
        record.architecture = stringField(config, "architecture");
        record.variant = stringField(config, "variant");
        record.osVersion = stringField(config, "os.version");
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
        // Nothing below may escape: this runs on the module thread, and an exception here
        // unwinds the whole scan loop and takes the module down for the lifetime of the
        // process. One unreadable source costs that source only.
        try
        {
            std::error_code errorCode;
            const std::filesystem::path path {m_layoutPath};

            if (m_layoutPath.empty() || !std::filesystem::is_directory(path, errorCode))
            {
                logWarn("Local path is not a directory: " + m_layoutPath);
                return {};
            }

            const auto format = detectFormat(path);

            if (format != LocalFormat::OciLayout)
            {
                logWarn("NOT IMPLEMENTED: local format '" + formatName(format) + "' at '" + m_layoutPath +
                        "' is not supported yet, skipping.");
                return {};
            }

            return readOciLayout(path);
        }
        catch (const std::exception& ex)
        {
            logWarn("Could not read the local path '" + m_layoutPath + "': " + ex.what());
        }
        catch (...)
        {
            logWarn("Could not read the local path '" + m_layoutPath + "': unknown error.");
        }

        return {};
    }

    std::vector<ImageReferenceRecord> LocalImageReader::readOciLayout(const std::filesystem::path& layoutPath)
    {
        std::vector<ImageReferenceRecord> records;

        const auto index = readJsonFile(layoutPath / OCI_INDEX_FILE);
        const auto manifests = index.find("manifests");

        if (manifests == index.end() || !manifests->is_array())
        {
            logDebug("Index has no manifests at: " + layoutPath.string());
            return records;
        }

        for (const auto& manifestRef : *manifests)
        {
            try
            {
                const auto manifestDigest = stringField(manifestRef, "digest");

                if (manifestDigest.empty())
                {
                    logDebug("Index entry without a digest at: " + layoutPath.string());
                    continue;
                }

                const auto manifestPath = blobPath(layoutPath, manifestDigest);

                if (manifestPath.empty())
                {
                    continue;
                }

                const auto manifest = readJsonFile(manifestPath);
                const auto configNode = manifest.find("config");
                const auto configDigest =
                    configNode != manifest.end() ? stringField(*configNode, "digest") : std::string {};

                if (configDigest.empty())
                {
                    logDebug("Manifest without config digest: " + manifestDigest);
                    continue;
                }

                const auto configPath = blobPath(layoutPath, configDigest);

                if (configPath.empty())
                {
                    continue;
                }

                ImageReferenceRecord record;
                record.configDigest = configDigest;
                record.manifestDigest = manifestDigest;

                applyConfigMetadata(readJsonFile(configPath), record);

                const auto annotations = manifestRef.find("annotations");

                if (annotations != manifestRef.end())
                {
                    record.tag = stringField(*annotations, "org.opencontainers.image.ref.name");
                }

                record.source = {SOURCE_TYPE, layoutPath.string()};
                records.push_back(std::move(record));
            }
            catch (const std::exception& ex)
            {
                logWarn("Skipping a manifest entry at '" + layoutPath.string() + "': " + ex.what());
            }
        }

        return records;
    }
} // namespace containerimages
