/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "archive_image_reader.hpp"
#include "byte_stream.hpp"
#include "ci_logging_helper.hpp"
#include "container_images_config.hpp"
#include "layer_composer.hpp"
#include "layer_reader.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <set>
#include <string>
#include <utility>

#include <json.hpp>

namespace
{
    const std::string OCI_LAYOUT_MARKER {"oci-layout"};
    const std::string OCI_INDEX_FILE {"index.json"};
    const std::string DOCKER_MANIFEST_FILE {"manifest.json"};
    const std::string BLOBS_DIR {"blobs"};

    // The containerd content store belongs to the container engine, which is the `<local>`
    // reference type and a follow-up issue.
    const std::string CONTAINERD_MARKER {"io.containerd.content.v1.content"};

    // Annotations that name an image in an index. The OCI one carries only the tag, while
    // the containerd one carries the whole reference, which is the name the image is really
    // known by, so it is preferred and both are reported.
    const std::string ANNOTATION_IMAGE_NAME {"io.containerd.image.name"};
    const std::string ANNOTATION_REF_NAME {"org.opencontainers.image.ref.name"};

    // Largest metadata file the reader will parse. An OCI index, a manifest or a
    // configuration blob is a few kilobytes, so anything past this ceiling is not
    // something this module should read into memory.
    constexpr std::uintmax_t MAX_METADATA_FILE_SIZE {16 * 1024 * 1024};

    // How deep a chain of image indexes is followed. A multi-platform image points at one
    // index of manifests; this bounds the nesting only, not the fan-out, which is what
    // MAX_INDEX_NODES and the visited-digest set below are for.
    constexpr int MAX_INDEX_DEPTH {4};

    // Total manifest-index entries walked across one reader's whole traversal, nested
    // levels included. A real multi-platform image has a handful of entries; this ceiling
    // is generous headroom above that. Without it, a self-referencing index with fan-out N
    // is walked N^MAX_INDEX_DEPTH times: the depth cap alone does not stop that growth.
    constexpr int MAX_INDEX_NODES {256};

    // Largest number of metadata-shaped members a saved archive's first pass will retain.
    // A real saved archive has a handful (index.json/manifest.json plus one config blob per
    // image); this bounds how much a crafted archive can make the reader hold in memory
    // between the first pass and the second.
    constexpr std::size_t MAX_METADATA_FILES {256};

    // Ceiling on the decompressed bytes read out of one layer blob. LayerReader walks the
    // full decompressed content of a layer, including the entries it skips, so an
    // attacker-controlled compression ratio otherwise bounds nothing: a few MiB of gzip can
    // expand past what the module could ever need to read in looking for a package
    // database. 8 GiB is comfortably above a real single-layer uncompressed size while
    // keeping the worst case bounded to a few seconds instead of hours.
    constexpr std::uint64_t MAX_LAYER_DECOMPRESSED_SIZE {8ULL * 1024 * 1024 * 1024};

    void logDebug(const std::string& message)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, message);
    }

    void logWarn(const std::string& message)
    {
        LoggingHelper::getInstance().log(LOG_WARNING, message);
    }

    /// @brief Recognized on-disk layouts.
    enum class InputFormat
    {
        OciLayout,      ///< OCI image layout directory.
        DockerLayout,   ///< `docker save` layout, extracted into a directory.
        Containerd,     ///< containerd content store, reserved for the engine store.
        Unknown         ///< Could not be identified.
    };

    /// @brief Inspect a directory and decide which layout it holds.
    InputFormat detectFormat(const std::filesystem::path& path)
    {
        std::error_code errorCode;

        if (std::filesystem::exists(path / OCI_LAYOUT_MARKER, errorCode))
        {
            return InputFormat::OciLayout;
        }

        if (std::filesystem::exists(path / CONTAINERD_MARKER, errorCode))
        {
            return InputFormat::Containerd;
        }

        if (std::filesystem::exists(path / DOCKER_MANIFEST_FILE, errorCode))
        {
            return InputFormat::DockerLayout;
        }

        return InputFormat::Unknown;
    }

    /// @brief One image found in the metadata, with everything needed to read its layers.
    struct ImageDescriptor
    {
        std::string manifestDigest;
        std::string configDigest;
        std::string tag;
        std::vector<std::string> tags;
        nlohmann::json config {nlohmann::json::object()};
        std::vector<std::string> layerKeys; ///< Layer keys in manifest order.
    };

    /// @brief Reads a metadata file by key. Returns an empty string when it is absent.
    ///
    /// A key is a path relative to the layout root, which is a path under a directory and
    /// a member name inside an archive. Both inputs are read through this one function,
    /// so the metadata parsing below is shared.
    using MetadataFetch = std::function<std::string(const std::string&)>;

    /// @brief Reads the package databases of one layer, by key.
    using LayerFetch = std::function<containerimages::LayerSnapshot(const std::string&)>;

    /// @brief Parse a metadata document, returning an empty object on failure.
    nlohmann::json parseJson(const std::string& content)
    {
        if (content.empty())
        {
            return nlohmann::json::object();
        }

        // Non-throwing parse: a discarded value is returned on malformed input, and it is
        // not an object, so it would fail every accessor below. Copy-initialized on purpose:
        // brace-initializing a json from a json selects its initializer-list constructor,
        // which would wrap the document in an array.
        auto document = nlohmann::json::parse(content, nullptr, false);

        return document.is_object() ? document : nlohmann::json::object();
    }

    /// @brief Read a string field, or an empty string when the node is not an object, the
    /// field is missing, or the field is not a string.
    ///
    /// Every field below comes from image metadata that may be attacker-influenced, so no
    /// accessor may assume a type: nlohmann::json::value() throws on both counts.
    std::string stringField(const nlohmann::json& node, const std::string& key)
    {
        if (!node.is_object())
        {
            return {};
        }

        const auto field {node.find(key)};

        return (field != node.end() && field->is_string()) ? field->get<std::string>() : std::string {};
    }

    /// @brief Read an array field, or an empty array when it is missing or not an array.
    nlohmann::json arrayField(const nlohmann::json& node, const std::string& key)
    {
        if (!node.is_object())
        {
            return nlohmann::json::array();
        }

        const auto field {node.find(key)};

        return (field != node.end() && field->is_array()) ? *field : nlohmann::json::array();
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

    /// @brief Resolve a digest ("sha256:abc...") to its blob key under the layout.
    /// Returns an empty key for malformed or unsafe digests.
    ///
    /// Both components are whitelisted rather than filtered for known-bad characters: a
    /// blacklist still lets through things such as a Windows drive-relative "C:foo",
    /// which operator/ would use to replace the layout path entirely.
    std::string blobKey(const std::string& digest)
    {
        const auto separator {digest.find(':')};

        if (separator == std::string::npos)
        {
            return {};
        }

        const auto algorithm {digest.substr(0, separator)};
        const auto value {digest.substr(separator + 1)};

        if (!isSafeDigestAlgorithm(algorithm) || !isSafeDigestEncoded(value))
        {
            logDebug("Rejected unsafe digest: " + digest);
            return {};
        }

        return BLOBS_DIR + "/" + algorithm + "/" + value;
    }

    /// @brief True if a key read from image metadata is a safe path relative to the layout.
    ///
    /// The `docker save` layout names its members directly rather than by digest, so the
    /// keys are checked instead of rebuilt: an absolute path or a parent reference would
    /// otherwise read a file outside the layout.
    bool isSafeRelativeKey(const std::string& key)
    {
        if (key.empty() || key.front() == '/' || key.find('\\') != std::string::npos ||
            key.find(':') != std::string::npos)
        {
            return false;
        }

        std::size_t start {0};

        while (start <= key.size())
        {
            const auto separator {key.find('/', start)};
            const auto segment {key.substr(start, separator == std::string::npos ? std::string::npos : separator - start)};

            if (segment == ".." || segment.empty())
            {
                return false;
            }

            if (separator == std::string::npos)
            {
                break;
            }

            start = separator + 1;
        }

        return true;
    }

    /// @brief Digest of the blob a `docker save` key names.
    ///
    /// That layout names its files rather than its digests: the modern form is
    /// `blobs/<algorithm>/<value>` and the older one is `<value>.json`, whose algorithm is
    /// always sha256. An unrecognized shape yields an empty digest, which is metadata
    /// only and never part of an identity.
    std::string digestFromKey(const std::string& key)
    {
        const auto blobsPrefix {BLOBS_DIR + "/"};

        if (key.rfind(blobsPrefix, 0) == 0)
        {
            const auto separator {key.find('/', blobsPrefix.size())};

            if (separator == std::string::npos)
            {
                return {};
            }

            const auto algorithm {key.substr(blobsPrefix.size(), separator - blobsPrefix.size())};
            const auto value {key.substr(separator + 1)};

            return (isSafeDigestAlgorithm(algorithm) && isSafeDigestEncoded(value)) ? algorithm + ":" + value
                   : std::string {};
        }

        const std::string suffix {".json"};

        if (key.size() > suffix.size() && key.compare(key.size() - suffix.size(), suffix.size(), suffix) == 0)
        {
            const auto value {key.substr(0, key.size() - suffix.size())};

            return isSafeDigestEncoded(value) ? "sha256:" + value : std::string {};
        }

        return {};
    }

    /// @brief Fill platform metadata from a parsed configuration blob.
    void applyConfigMetadata(const nlohmann::json& config, containerimages::ImageReferenceRecord& record)
    {
        record.os = stringField(config, "os");
        record.architecture = stringField(config, "architecture");
        record.variant = stringField(config, "variant");
        record.osVersion = stringField(config, "os.version");
    }

    /// @brief True when an index entry's platform marks it as an attestation or
    /// provenance manifest rather than a real image: buildx and containerd both write
    /// "unknown"/"unknown" as the platform of those, since they carry no image content.
    bool isAttestationManifest(const nlohmann::json& entry)
    {
        if (!entry.is_object())
        {
            return false;
        }

        const auto platform {entry.find("platform")};

        if (platform == entry.end() || !platform->is_object())
        {
            return false;
        }

        return stringField(*platform, "os") == "unknown" || stringField(*platform, "architecture") == "unknown";
    }

    /// @brief Collect the descriptors an OCI manifest, or an index of manifests, points to.
    ///
    /// @param visited Digests already walked in this traversal, shared across every entry
    ///        of the top-level index: stops a cycle in attacker-influenced metadata dead,
    ///        regardless of fan-out.
    /// @param nodesVisited Total entries walked so far, shared the same way: bounds the
    ///        overall work even when every node is distinct, since MAX_INDEX_DEPTH alone
    ///        bounds nesting, not fan-out.
    void collectOciDescriptors(const MetadataFetch& metadata,
                               const nlohmann::json& entry,
                               const int depth,
                               std::set<std::string>& visited,
                               int& nodesVisited,
                               std::vector<ImageDescriptor>& descriptors)
    {
        if (depth > MAX_INDEX_DEPTH)
        {
            logWarn("Image index nested deeper than supported, skipping the rest.");
            return;
        }

        if (++nodesVisited > MAX_INDEX_NODES)
        {
            logWarn("Image index has more manifest entries than supported, skipping the rest.");
            return;
        }

        if (isAttestationManifest(entry))
        {
            logDebug("Skipping an attestation or provenance manifest entry.");
            return;
        }

        const auto digest {stringField(entry, "digest")};
        const auto key {digest.empty() ? std::string {} : blobKey(digest)};

        if (key.empty())
        {
            logDebug("Index entry without a usable digest.");
            return;
        }

        if (!visited.insert(digest).second)
        {
            logDebug("Index entry already visited, skipping to avoid a cycle: " + digest);
            return;
        }

        const auto document = parseJson(metadata(key));

        // A multi-platform image points at an index of manifests instead of a manifest.
        const auto nested = arrayField(document, "manifests");

        if (!nested.empty())
        {
            for (const auto& child : nested)
            {
                collectOciDescriptors(metadata, child, depth + 1, visited, nodesVisited, descriptors);
            }

            return;
        }

        const auto configNode {document.find("config")};
        const auto configDigest {configNode != document.end() ? stringField(*configNode, "digest") : std::string {}};

        if (configDigest.empty())
        {
            logDebug("Manifest without a config digest: " + digest);
            return;
        }

        const auto configKey {blobKey(configDigest)};

        if (configKey.empty())
        {
            return;
        }

        ImageDescriptor descriptor;
        descriptor.manifestDigest = digest;
        descriptor.configDigest = configDigest;
        descriptor.config = parseJson(metadata(configKey));

        const auto annotations {entry.is_object() ? entry.find("annotations") : entry.end()};

        if (entry.is_object() && annotations != entry.end())
        {
            const auto imageName {stringField(*annotations, ANNOTATION_IMAGE_NAME)};
            const auto refName {stringField(*annotations, ANNOTATION_REF_NAME)};

            // The whole reference is the display name when the index carries it; the tag-only
            // annotation is the fallback, and both are kept when they differ.
            descriptor.tag = imageName.empty() ? refName : imageName;

            for (const auto& name : {imageName, refName})
            {
                if (!name.empty() && std::find(descriptor.tags.begin(), descriptor.tags.end(), name) ==
                        descriptor.tags.end())
                {
                    descriptor.tags.push_back(name);
                }
            }
        }

        for (const auto& layer : arrayField(document, "layers"))
        {
            const auto layerKey {blobKey(stringField(layer, "digest"))};

            if (!layerKey.empty())
            {
                descriptor.layerKeys.push_back(layerKey);
            }
        }

        descriptors.push_back(std::move(descriptor));
    }

    /// @brief Build the descriptors of an OCI image layout.
    std::vector<ImageDescriptor> ociDescriptors(const MetadataFetch& metadata)
    {
        std::vector<ImageDescriptor> descriptors;

        const auto index = parseJson(metadata(OCI_INDEX_FILE));
        const auto manifests = arrayField(index, "manifests");

        if (manifests.empty())
        {
            logDebug("Image index lists no manifests.");
            return descriptors;
        }

        std::set<std::string> visited;
        int nodesVisited {0};

        for (const auto& entry : manifests)
        {
            try
            {
                collectOciDescriptors(metadata, entry, 0, visited, nodesVisited, descriptors);
            }
            catch (const std::exception& ex)
            {
                logWarn(std::string {"Skipping a manifest entry: "} + ex.what());
            }
        }

        return descriptors;
    }

    /// @brief Build the descriptors of a `docker save` layout.
    ///
    /// Its `manifest.json` is an array of images, each naming its configuration file, its
    /// layers in order, and the tags it was saved under.
    std::vector<ImageDescriptor> dockerDescriptors(const MetadataFetch& metadata)
    {
        std::vector<ImageDescriptor> descriptors;

        auto document = nlohmann::json::parse(metadata(DOCKER_MANIFEST_FILE), nullptr, false);

        if (!document.is_array())
        {
            logDebug("Saved image manifest is not a list of images.");
            return descriptors;
        }

        for (const auto& entry : document)
        {
            if (!entry.is_object())
            {
                continue;
            }

            ImageDescriptor descriptor;
            const auto configKey {stringField(entry, "Config")};

            if (isSafeRelativeKey(configKey))
            {
                descriptor.config = parseJson(metadata(configKey));
                descriptor.configDigest = digestFromKey(configKey);
            }

            for (const auto& tag : arrayField(entry, "RepoTags"))
            {
                if (tag.is_string())
                {
                    descriptor.tags.push_back(tag.get<std::string>());
                }
            }

            if (!descriptor.tags.empty())
            {
                descriptor.tag = descriptor.tags.front();
            }

            for (const auto& layer : arrayField(entry, "Layers"))
            {
                if (!layer.is_string())
                {
                    continue;
                }

                const auto layerKey {layer.get<std::string>()};

                if (isSafeRelativeKey(layerKey))
                {
                    descriptor.layerKeys.push_back(layerKey);
                }
                else
                {
                    logDebug("Rejected unsafe layer key: " + layerKey);
                }
            }

            descriptors.push_back(std::move(descriptor));
        }

        return descriptors;
    }

    /// @brief Every layer key the descriptors refer to, without duplicates.
    std::set<std::string> layerKeysOf(const std::vector<ImageDescriptor>& descriptors)
    {
        std::set<std::string> keys;

        for (const auto& descriptor : descriptors)
        {
            keys.insert(descriptor.layerKeys.begin(), descriptor.layerKeys.end());
        }

        return keys;
    }

    /// @brief Turn descriptors and layer snapshots into inventory records.
    /// @brief Keep exactly one descriptor per reference.
    ///
    /// The references table's primary key is (reference_type, reference_value): one row
    /// per configured reference, by design and without a schema change in scope for this
    /// issue. An index or a saved archive naming more than one image, after attestation
    /// manifests are filtered out by collectOciDescriptors, cannot be represented as more
    /// than one row without one, so the first image is kept deterministically and the
    /// rest are named in a warning instead of silently colliding into the same row on
    /// every scan.
    void keepPrimaryDescriptor(std::vector<ImageDescriptor>& descriptors, const std::string& location)
    {
        if (descriptors.size() <= 1)
        {
            return;
        }

        std::string skipped;

        for (std::size_t i = 1; i < descriptors.size(); ++i)
        {
            const auto& name {descriptors[i].tag.empty() ? descriptors[i].manifestDigest : descriptors[i].tag};
            skipped += skipped.empty() ? name : ", " + name;
        }

        const auto& kept {descriptors.front().tag.empty() ? descriptors.front().manifestDigest : descriptors.front().tag};

        logWarn("Reference '" + location + "' names " + std::to_string(descriptors.size()) +
                " images; only '" + kept + "' is inventoried under this reference. Skipped: " + skipped +
                ". Configure each image as its own <archive> reference to inventory it.");

        descriptors.resize(1);
    }

    std::vector<containerimages::ImageReferenceRecord> buildRecords(const std::vector<ImageDescriptor>& descriptors,
                                                                    const LayerFetch& layers,
                                                                    const std::string& sourceType,
                                                                    const std::string& location)
    {
        std::vector<containerimages::ImageReferenceRecord> records;

        for (const auto& descriptor : descriptors)
        {
            containerimages::ImageReferenceRecord record;
            record.source = {sourceType, location};
            record.manifestDigest = descriptor.manifestDigest;
            record.configDigest = descriptor.configDigest;
            record.tag = descriptor.tag;
            record.tags = descriptor.tags;
            applyConfigMetadata(descriptor.config, record);

            containerimages::LayerComposer composer;

            for (const auto& key : descriptor.layerKeys)
            {
                composer.apply(layers(key));
            }

            record.packages = composer.packages();

            if (record.packages.empty())
            {
                const auto& unsupported {composer.unsupportedFormats()};

                if (!unsupported.empty())
                {
                    std::string formats;

                    for (const auto& format : unsupported)
                    {
                        formats += formats.empty() ? format : ", " + format;
                    }

                    logWarn("NOT IMPLEMENTED: image at '" + location + "' uses the package format(s) " + formats +
                            ", which are recognized but not supported yet. Reporting zero packages.");
                }
                else
                {
                    logWarn("No supported package database found in the image at '" + location +
                            "'. Reporting zero packages.");
                }
            }

            logDebug("Reference '" + location + "' manifest=" + record.manifestDigest + " packages=" +
                     std::to_string(record.packages.size()) + ".");

            records.push_back(std::move(record));
        }

        return records;
    }

    /// @brief Read a metadata file from a layout directory.
    ///
    /// The file type is checked before opening: the path is built from on-disk data and
    /// opening a FIFO with no writer would block the module thread indefinitely, past the
    /// point where a stop can reach it.
    std::string readMetadataFile(const std::filesystem::path& path)
    {
        std::error_code errorCode;

        if (!std::filesystem::is_regular_file(path, errorCode))
        {
            logDebug("Not a regular metadata file: " + path.string());
            return {};
        }

        const auto size {std::filesystem::file_size(path, errorCode)};

        if (errorCode)
        {
            logWarn("Could not get the size of file: " + path.string());
            return {};
        }

        if (size > MAX_METADATA_FILE_SIZE)
        {
            logWarn("Metadata file is larger than the " + std::to_string(MAX_METADATA_FILE_SIZE) +
                    " byte limit, skipping: " + path.string());
            return {};
        }

        std::ifstream stream {path, std::ios::binary};

        if (!stream.is_open())
        {
            logDebug("Could not open file: " + path.string());
            return {};
        }

        return std::string {std::istreambuf_iterator<char> {stream}, std::istreambuf_iterator<char> {}};
    }

    /// @brief True when a member of a saved archive is small enough and looks like the JSON
    /// metadata the reader needs.
    ///
    /// A saved archive names its blobs by digest, so a manifest and a layer are told apart
    /// by their content: a JSON document starts with `{` or `[`, and a tar member never
    /// does, since a tar starts with the name of its first entry.
    bool looksLikeMetadata(const std::string& content)
    {
        for (const auto character : content)
        {
            if (character == ' ' || character == '\t' || character == '\r' || character == '\n')
            {
                continue;
            }

            return character == '{' || character == '[';
        }

        return false;
    }
} // namespace

namespace containerimages
{
    ArchiveImageReader::ArchiveImageReader(std::string location, std::string knownConfigDigest)
        : m_location {std::move(location)}
        , m_knownConfigDigest {std::move(knownConfigDigest)}
    {
    }

    std::string ArchiveImageReader::sourceType() const
    {
        return referenceTypeName(ReferenceType::Archive);
    }

    ImageReadResult ArchiveImageReader::discover()
    {
        // Nothing below may escape: this runs on the module thread, and an exception here
        // unwinds the whole scan loop and takes the module down for the lifetime of the
        // process. One unreadable reference costs that reference only.
        try
        {
            std::error_code errorCode;
            const std::filesystem::path path {m_location};

            if (m_location.empty())
            {
                logWarn("Empty archive reference, skipping.");
                return ImageReadResult::failed();
            }

            if (std::filesystem::is_directory(path, errorCode))
            {
                return readDirectory(path);
            }

            if (std::filesystem::is_regular_file(path, errorCode))
            {
                return readSavedArchive(path);
            }

            logWarn("Archive reference is neither a file nor a directory: " + m_location);
        }
        catch (const std::exception& ex)
        {
            logWarn("Could not read the archive reference '" + m_location + "': " + ex.what());
        }
        catch (...)
        {
            logWarn("Could not read the archive reference '" + m_location + "': unknown error.");
        }

        return ImageReadResult::failed();
    }

    ImageReadResult ArchiveImageReader::readDirectory(const std::filesystem::path& path)
    {
        const auto format {detectFormat(path)};

        if (format == InputFormat::Containerd)
        {
            logWarn("NOT IMPLEMENTED: the containerd content store at '" + m_location +
                    "' is read through the container engine, which is not supported yet. Skipping.");
            return ImageReadResult::failed();
        }

        if (format == InputFormat::Unknown)
        {
            logWarn("Directory '" + m_location + "' is not an OCI image layout nor a saved image layout, skipping.");
            return ImageReadResult::failed();
        }

        const MetadataFetch metadata {[&path](const std::string & key)
        {
            return isSafeRelativeKey(key) ? readMetadataFile(path / key) : std::string {};
        }};

        auto descriptors {format == InputFormat::OciLayout ? ociDescriptors(metadata) : dockerDescriptors(metadata)};
        keepPrimaryDescriptor(descriptors, m_location);

        // The configuration blob digest identifies the image's contents, so an image still
        // reporting the digest already stored cannot have different packages. Reading its
        // layers again would produce the inventory that is already there, so it is skipped
        // and the caller keeps what it has. Reading the metadata is what makes this cheap:
        // the layers, which are the expensive part, are never opened.
        if (!m_knownConfigDigest.empty() && !descriptors.empty() &&
                descriptors.front().configDigest == m_knownConfigDigest)
        {
            logDebug("Reference '" + m_location + "' still reports " + m_knownConfigDigest +
                     ", so its layers were not read again.");
            return ImageReadResult::unchanged();
        }

        // Every layer is read once, even when two manifests of a multi-platform image
        // share it.
        std::map<std::string, LayerSnapshot> snapshots;

        for (const auto& key : layerKeysOf(descriptors))
        {
            std::error_code errorCode;

            if (!std::filesystem::is_regular_file(path / key, errorCode))
            {
                // Opening a FIFO with no writer would block the module thread
                // indefinitely, past the point where a stop can reach it; readMetadataFile
                // applies the same guard for the metadata files of this layout.
                logDebug("Not a regular layer blob: " + key);
                continue;
            }

            FileByteStream file {path / key};

            if (!file.isOpen())
            {
                logWarn("Could not open the layer '" + key + "' of '" + m_location + "'.");
                continue;
            }

            LayerByteStream blob {file};

            if (!isCompressionSupported(blob.compression()))
            {
                logWarn("NOT IMPLEMENTED: layer '" + key + "' of '" + m_location + "' is " +
                        compressionName(blob.compression()) +
                        " compressed, which is recognized but not supported yet. Skipping it.");
                continue;
            }

            BoundedByteStream layer {blob, MAX_LAYER_DECOMPRESSED_SIZE};
            auto snapshot {readLayerSnapshot(layer)};

            if (!snapshot.complete)
            {
                logWarn("Layer '" + key + "' of '" + m_location + "' is malformed or truncated, reading what it gave.");
            }

            snapshots.emplace(key, std::move(snapshot));
        }

        const LayerFetch layers {[&snapshots](const std::string & key)
        {
            const auto snapshot {snapshots.find(key)};
            return snapshot == snapshots.end() ? LayerSnapshot {} : snapshot->second;
        }};

        return ImageReadResult::success(buildRecords(descriptors, layers, sourceType(), m_location));
    }

    ImageReadResult ArchiveImageReader::readSavedArchive(const std::filesystem::path& path)
    {
        // A tar is read from start to end, while the layer order comes from the metadata
        // inside it, so the archive is read twice: once for the metadata, once for the
        // layers the metadata named. Only the package databases are kept in memory.
        std::map<std::string, std::string> metadataFiles;

        {
            FileByteStream file {path};

            if (!file.isOpen())
            {
                logWarn("Could not open the saved image archive '" + m_location + "'.");
                return ImageReadResult::failed();
            }

            LayerByteStream archive {file};
            bool metadataCapLogged {false};
            const auto complete {LayerReader::read(archive, [&](const LayerEntry & entry, IByteStream & content)
            {
                if (!entry.isRegularFile || entry.size == 0 || entry.size > MAX_METADATA_FILE_SIZE)
                {
                    return true;
                }

                std::string buffer;
                buffer.resize(static_cast<std::size_t>(entry.size));
                buffer.resize(readExact(content, buffer.data(), buffer.size()));

                if (!looksLikeMetadata(buffer))
                {
                    return true;
                }

                if (metadataFiles.size() >= MAX_METADATA_FILES && metadataFiles.count(entry.path) == 0)
                {
                    if (!metadataCapLogged)
                    {
                        logWarn("Saved image archive '" + m_location +
                                "' has more metadata-shaped members than supported, ignoring the rest.");
                        metadataCapLogged = true;
                    }

                    return true;
                }

                // Tar is last-wins on a duplicated member name; emplace() would keep the
                // first instead, so this uses assignment.
                metadataFiles[entry.path] = std::move(buffer);

                return true;
            })};

            if (!complete)
            {
                logWarn("Saved image archive '" + m_location + "' is malformed or truncated.");
            }
        }

        const MetadataFetch metadata {[&metadataFiles](const std::string & key)
        {
            const auto file {metadataFiles.find(key)};
            return file == metadataFiles.end() ? std::string {} : file->second;
        }};

        const auto isOciLayout {metadataFiles.count(OCI_INDEX_FILE) > 0};
        auto descriptors {isOciLayout ? ociDescriptors(metadata) : dockerDescriptors(metadata)};

        if (descriptors.empty())
        {
            logWarn("No image manifest found in the saved image archive '" + m_location + "'.");
            return ImageReadResult::failed();
        }

        keepPrimaryDescriptor(descriptors, m_location);

        // The configuration blob digest identifies the image's contents, so an image still
        // reporting the digest already stored cannot have different packages. Reading its
        // layers again would produce the inventory that is already there, so it is skipped
        // and the caller keeps what it has. Reading the metadata is what makes this cheap:
        // the layers, which are the expensive part, are never opened.
        if (!m_knownConfigDigest.empty() && !descriptors.empty() &&
                descriptors.front().configDigest == m_knownConfigDigest)
        {
            logDebug("Reference '" + m_location + "' still reports " + m_knownConfigDigest +
                     ", so its layers were not read again.");
            return ImageReadResult::unchanged();
        }

        const auto wanted {layerKeysOf(descriptors)};
        std::map<std::string, LayerSnapshot> snapshots;

        {
            FileByteStream file {path};
            LayerByteStream archive {file};

            const auto layersComplete {LayerReader::read(archive, [&](const LayerEntry & entry, IByteStream & content)
            {
                if (!entry.isRegularFile || wanted.count(entry.path) == 0)
                {
                    return true;
                }

                LayerByteStream blob {content};

                if (!isCompressionSupported(blob.compression()))
                {
                    logWarn("NOT IMPLEMENTED: layer '" + entry.path + "' of '" + m_location + "' is " +
                            compressionName(blob.compression()) +
                            " compressed, which is recognized but not supported yet. Skipping it.");
                    return true;
                }

                BoundedByteStream layer {blob, MAX_LAYER_DECOMPRESSED_SIZE};
                auto snapshot {readLayerSnapshot(layer)};

                if (!snapshot.complete)
                {
                    logWarn("Layer '" + entry.path + "' of '" + m_location +
                            "' is malformed or truncated, reading what it gave.");
                }

                // Tar is last-wins on a duplicated member name; emplace() would keep the
                // first instead, so this uses assignment.
                snapshots[entry.path] = std::move(snapshot);
                return true;
            })};

            if (!layersComplete)
            {
                logWarn("Saved image archive '" + m_location + "' is malformed or truncated (layer pass).");
            }
        }

        const LayerFetch layers {[&snapshots](const std::string & key)
        {
            const auto snapshot {snapshots.find(key)};
            return snapshot == snapshots.end() ? LayerSnapshot {} : snapshot->second;
        }};

        return ImageReadResult::success(buildRecords(descriptors, layers, sourceType(), m_location));
    }
} // namespace containerimages
