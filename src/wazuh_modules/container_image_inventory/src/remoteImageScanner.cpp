/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "remoteImageScanner.hpp"

#include <chrono>
#include <sstream>
#include <stdexcept>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>

#include "imageArchiveParser.hpp"
#include "overlayFsResolver.hpp"
#include "packageDbExtractor.hpp"
#include "packageInventoryScanner.hpp"

namespace container_image_inventory
{
    namespace
    {
        constexpr const char* OCI_INDEX = "application/vnd.oci.image.index.v1+json";
        constexpr const char* OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json";
        constexpr const char* DOCKER_LIST = "application/vnd.docker.distribution.manifest.list.v2+json";
        constexpr const char* DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json";

        // BlobProvider backed by RegistryClient with optional disk + memory cache.
        class RegistryBlobProvider : public BlobProvider
        {
        public:
            RegistryBlobProvider(RegistryClient& client, DigestCache* cache, TraceFn trace)
                : m_client(client), m_cache(cache), m_trace(std::move(trace))
            {
            }

            std::vector<unsigned char> get_blob(const std::string& key) override
            {
                auto it = m_memory.find(key);
                if (it != m_memory.end())
                {
                    return it->second;
                }
                if (m_cache && m_cache->blob_cache_enabled() && m_cache->has_blob(key))
                {
                    auto data = m_cache->read_blob(key);
                    if (data.has_value())
                    {
                        if (m_trace)
                        {
                            m_trace("blob cache hit digest=" + key +
                                    " bytes=" + std::to_string(data->size()));
                        }
                        m_memory[key] = *data;
                        return *data;
                    }
                }
                auto bytes = m_client.fetch_blob(key);
                if (m_trace)
                {
                    m_trace("blob downloaded digest=" + key +
                            " bytes=" + std::to_string(bytes.size()));
                }
                if (m_cache && m_cache->blob_cache_enabled())
                {
                    m_cache->write_blob(key, bytes);
                }
                m_memory[key] = bytes;
                return bytes;
            }

        private:
            RegistryClient& m_client;
            DigestCache* m_cache;
            TraceFn m_trace;
            std::unordered_map<std::string, std::vector<unsigned char>> m_memory;
        };

        bool is_index(const std::string& mt)
        {
            return mt == OCI_INDEX || mt == DOCKER_LIST;
        }

        bool is_manifest(const std::string& mt)
        {
            return mt == OCI_MANIFEST || mt == DOCKER_MANIFEST;
        }
    } // namespace

    RemoteImageScanner::RemoteImageScanner(TraceFn trace)
        : m_trace(std::move(trace))
    {
    }

    void RemoteImageScanner::trace(const std::string& msg) const
    {
        if (m_trace)
        {
            m_trace(msg);
        }
    }

    RemoteScanResult RemoteImageScanner::scan(const RemoteScanOptions& opts)
    {
        const auto t0 = std::chrono::steady_clock::now();
        RemoteScanResult r;
        r.base.source_type = "remote";
        r.base.source_path = opts.image_ref;
        r.base.configured_ref = opts.image_ref;
        r.platform = opts.platform.empty() ? default_platform() : opts.platform;

        const auto parsed = parse_image_ref(opts.image_ref);
        r.registry = parsed.registry;
        r.repository = parsed.repository;
        r.reference = parsed.reference;
        trace("remote scan started ref=" + opts.image_ref + " platform=" + r.platform);
        trace("parsed ref registry=" + parsed.registry + " repository=" + parsed.repository +
              " reference=" + parsed.reference);

        RegistryClient client(parsed, opts.auth, m_trace);

        trace("fetching manifest reference=" + parsed.reference);
        auto manifest_resp = client.fetch_manifest(parsed.reference);
        r.root_digest = manifest_resp.docker_content_digest;
        trace("manifest resolved media_type=" + manifest_resp.media_type +
              " root_digest=" + r.root_digest);

        nlohmann::json root_json;
        try
        {
            root_json = nlohmann::json::parse(manifest_resp.body);
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(std::string("manifest JSON parse failed: ") + e.what());
        }

        std::string image_manifest_body = manifest_resp.body;
        std::string image_manifest_media = manifest_resp.media_type;

        // If the response is an index/list, select platform descriptor.
        if (is_index(manifest_resp.media_type) ||
            (manifest_resp.media_type.empty() && root_json.contains("manifests")))
        {
            const auto plat = parse_platform(r.platform);
            std::string descriptor_digest;
            for (const auto& d : root_json.at("manifests"))
            {
                if (!d.contains("platform"))
                {
                    continue;
                }
                const auto& p = d.at("platform");
                if (p.value("os", "") != plat.os)
                {
                    continue;
                }
                if (p.value("architecture", "") != plat.arch)
                {
                    continue;
                }
                if (!plat.variant.empty() && p.value("variant", "") != plat.variant)
                {
                    continue;
                }
                if (p.value("os", "") == "unknown")
                {
                    continue;
                }
                descriptor_digest = d.value("digest", "");
                if (!descriptor_digest.empty())
                {
                    break;
                }
            }
            if (descriptor_digest.empty())
            {
                throw std::runtime_error("no manifest found for platform " + r.platform);
            }
            trace("selected platform manifest digest=" + descriptor_digest);
            r.selected_manifest_digest = descriptor_digest;
            const auto child = client.fetch_manifest(descriptor_digest);
            image_manifest_body = child.body;
            image_manifest_media = child.media_type;
            try
            {
                root_json = nlohmann::json::parse(image_manifest_body);
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(std::string("child manifest parse failed: ") +
                                         e.what());
            }
        }
        else if (is_manifest(manifest_resp.media_type) || root_json.contains("layers"))
        {
            r.selected_manifest_digest = r.root_digest;
        }
        else
        {
            throw std::runtime_error("unsupported media type: " + manifest_resp.media_type);
        }

        // From here root_json must be an image manifest.
        const std::string config_digest =
            root_json.value("config", nlohmann::json::object()).value("digest", "");
        if (config_digest.empty())
        {
            throw std::runtime_error("manifest missing config.digest");
        }

        DigestCache cache(opts.cache_dir, opts.use_blob_cache, m_trace);
        cache.write_ref_record(parsed.registry, parsed.repository, parsed.reference,
                               r.platform, r.root_digest, r.selected_manifest_digest);

        // Cache lookup by selected_manifest_digest.
        const bool can_cache_result =
            opts.use_result_cache && !r.selected_manifest_digest.empty();
        if (can_cache_result && cache.has_result(r.selected_manifest_digest))
        {
            trace("cache lookup selected_manifest_digest=" + r.selected_manifest_digest +
                  " hit=true");
            auto cached = cache.read_result(r.selected_manifest_digest);
            if (cached.has_value())
            {
                const auto& j = *cached;
                r.cache_hit = true;
                if (j.contains("image"))
                {
                    const auto& img = j["image"];
                    r.base.image.os = img.value("os", "linux");
                    r.base.image.architecture = img.value("architecture", "");
                    r.base.image.image_id = img.value("image_id", "");
                    r.base.image.config_digest = img.value("config_digest", "");
                    r.base.image.layer_count = img.value("layer_count", 0);
                    if (img.contains("repo_tags") && img["repo_tags"].is_array())
                    {
                        for (const auto& t : img["repo_tags"])
                        {
                            if (t.is_string())
                            {
                                r.base.image.repo_tags.push_back(t.get<std::string>());
                            }
                        }
                    }
                }
                if (j.contains("scan"))
                {
                    const auto& s = j["scan"];
                    r.base.package_manager = s.value("package_manager", "none");
                    if (!s.value("rpm_backend", nlohmann::json()).is_null() &&
                        s.value("rpm_backend", nlohmann::json()).is_string())
                    {
                        r.base.rpm_backend = s["rpm_backend"].get<std::string>();
                    }
                    r.base.database_path = s.value("database_path", "");
                    r.base.package_count = s.value("package_count", 0);
                }
                if (j.contains("packages") && j["packages"].is_array())
                {
                    for (const auto& pj : j["packages"])
                    {
                        Package p;
                        p.name = pj.value("name", "");
                        p.version_ = pj.value("version_", "");
                        p.architecture = pj.value("architecture", " ");
                        p.size = pj.value("size", static_cast<int64_t>(0));
                        p.description = pj.value("description", " ");
                        p.priority = pj.value("priority", " ");
                        p.category = pj.value("category", " ");
                        p.source = pj.value("source", " ");
                        p.multiarch = pj.value("multiarch", " ");
                        p.vendor = pj.value("vendor", " ");
                        p.installed = pj.value("installed", " ");
                        p.path = pj.value("path", " ");
                        p.type = pj.value("type", "");
                        r.base.packages.push_back(std::move(p));
                    }
                }
                const auto t1 = std::chrono::steady_clock::now();
                r.base.elapsed_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
                trace("remote scan completed elapsed_ms=" + std::to_string(r.base.elapsed_ms) +
                      " cache_hit=true");
                return r;
            }
        }
        if (can_cache_result)
        {
            trace("cache lookup selected_manifest_digest=" + r.selected_manifest_digest +
                  " hit=false");
        }

        RegistryBlobProvider provider(client, &cache, m_trace);

        // Download config blob.
        auto config_bytes = provider.get_blob(config_digest);
        trace("config downloaded digest=" + config_digest +
              " bytes=" + std::to_string(config_bytes.size()));
        r.base.image.config_digest = config_digest;
        r.base.image.image_id = "sha256:" + sha256_hex(config_bytes.data(), config_bytes.size());
        try
        {
            const auto cfg =
                nlohmann::json::parse(std::string(config_bytes.begin(), config_bytes.end()));
            r.base.image.os = cfg.value("os", "linux");
            r.base.image.architecture = cfg.value("architecture", "unknown");
        }
        catch (const std::exception&)
        {
            // Leave defaults.
        }

        // Collect layer digests.
        std::vector<std::string> layer_digests;
        if (root_json.contains("layers") && root_json["layers"].is_array())
        {
            for (const auto& l : root_json["layers"])
            {
                if (l.contains("digest") && l["digest"].is_string())
                {
                    layer_digests.push_back(l["digest"].get<std::string>());
                }
            }
        }
        r.base.image.layer_count = static_cast<int>(layer_digests.size());
        trace("layers discovered count=" + std::to_string(layer_digests.size()));

        // Overlay resolution.
        const auto candidates = candidate_db_paths();
        std::unordered_set<std::string> wanted;
        for (const auto& c : candidates)
        {
            wanted.insert(c.path);
        }
        OverlayFsResolver resolver(m_trace);
        const auto vfs = resolver.resolve(provider, layer_digests, wanted);

        auto sel = pick_database(provider, vfs, m_trace);
        if (sel.backend == PackageBackend::None)
        {
            r.base.package_manager = "none";
        }
        else
        {
            r.base.database_path = sel.database_path;
            switch (sel.backend)
            {
                case PackageBackend::Dpkg:
                {
                    r.base.package_manager = "dpkg";
                    std::string content(reinterpret_cast<const char*>(sel.bytes.data()),
                                        sel.bytes.size());
                    r.base.packages = parse_dpkg(content);
                    break;
                }
                case PackageBackend::Apk:
                {
                    r.base.package_manager = "apk";
                    std::string content(reinterpret_cast<const char*>(sel.bytes.data()),
                                        sel.bytes.size());
                    r.base.packages = parse_apk(content);
                    break;
                }
                case PackageBackend::RpmSqlite:
                {
                    r.base.package_manager = "rpm";
                    r.base.rpm_backend = "sqlite";
                    const auto tmp = write_temp_file(sel.bytes, ".sqlite");
                    try
                    {
                        r.base.packages = parse_rpm_sqlite(tmp);
                        ::unlink(tmp.c_str());
                    }
                    catch (...)
                    {
                        ::unlink(tmp.c_str());
                        throw;
                    }
                    break;
                }
                case PackageBackend::RpmBdb:
                {
                    r.base.package_manager = "rpm";
                    r.base.rpm_backend = "bdb";
                    const auto tmp = write_temp_file(sel.bytes, ".Packages");
                    try
                    {
                        r.base.packages = parse_rpm_bdb(tmp);
                        ::unlink(tmp.c_str());
                    }
                    catch (...)
                    {
                        ::unlink(tmp.c_str());
                        throw;
                    }
                    break;
                }
                case PackageBackend::RpmNdbUnsupported:
                {
                    r.base.package_manager = "rpm";
                    r.base.rpm_backend = "ndb-unsupported";
                    trace("RPM NDB detected — backend not implemented in PoC");
                    break;
                }
                default:
                    break;
            }
        }
        r.base.package_count = static_cast<int>(r.base.packages.size());
        trace("packages parsed count=" + std::to_string(r.base.package_count));

        const auto t1 = std::chrono::steady_clock::now();
        r.base.elapsed_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        trace("remote scan completed elapsed_ms=" + std::to_string(r.base.elapsed_ms) +
              " cache_hit=false");

        if (can_cache_result)
        {
            cache.write_result(r.selected_manifest_digest, remote_result_to_json(r));
        }
        return r;
    }

    nlohmann::json remote_result_to_json(const RemoteScanResult& r)
    {
        nlohmann::json j;
        nlohmann::json src;
        src["type"] = "remote";
        src["configured_ref"] = r.base.configured_ref;
        src["registry"] = r.registry;
        src["repository"] = r.repository;
        src["reference"] = r.reference;
        src["platform"] = r.platform;
        j["source"] = src;

        nlohmann::json img;
        img["repo_tags"] = r.base.image.repo_tags;
        img["os"] = r.base.image.os;
        img["architecture"] = r.base.image.architecture;
        img["image_id"] = r.base.image.image_id;
        img["config_digest"] = r.base.image.config_digest;
        img["root_digest"] = r.root_digest;
        img["selected_manifest_digest"] = r.selected_manifest_digest;
        // manifest_digest preserves the archive-mode field name and equals the
        // platform-selected manifest digest for remote scans.
        img["manifest_digest"] = r.selected_manifest_digest;
        img["layer_count"] = r.base.image.layer_count;
        j["image"] = img;

        nlohmann::json scan;
        scan["package_manager"] = r.base.package_manager;
        if (r.base.rpm_backend.has_value())
        {
            scan["rpm_backend"] = *r.base.rpm_backend;
        }
        else
        {
            scan["rpm_backend"] = nullptr;
        }
        scan["database_path"] = r.base.database_path;
        scan["package_count"] = r.base.package_count;
        scan["elapsed_ms"] = r.base.elapsed_ms;
        scan["cache_hit"] = r.cache_hit;
        j["scan"] = scan;

        nlohmann::json pkgs = nlohmann::json::array();
        for (const auto& p : r.base.packages)
        {
            nlohmann::json o;
            o["name"] = p.name;
            o["version_"] = p.version_;
            o["architecture"] = p.architecture;
            o["size"] = p.size;
            o["description"] = p.description;
            o["priority"] = p.priority;
            o["category"] = p.category;
            o["source"] = p.source;
            o["multiarch"] = p.multiarch;
            o["vendor"] = p.vendor;
            o["installed"] = p.installed;
            o["path"] = p.path;
            o["type"] = p.type;
            pkgs.push_back(std::move(o));
        }
        j["packages"] = pkgs;
        return j;
    }

    std::string remote_result_to_summary(const RemoteScanResult& r)
    {
        std::ostringstream os;
        os << "source=remote ref=" << r.base.configured_ref
           << " platform=" << r.platform
           << " root_digest=" << (r.root_digest.empty() ? std::string("-") : r.root_digest)
           << " manifest=" << (r.selected_manifest_digest.empty() ? std::string("-") : r.selected_manifest_digest)
           << " pm=" << r.base.package_manager
           << " rpm_backend=" << (r.base.rpm_backend.has_value() ? *r.base.rpm_backend : std::string("null"))
           << " db=" << (r.base.database_path.empty() ? std::string("-") : r.base.database_path)
           << " count=" << r.base.package_count
           << " cache_hit=" << (r.cache_hit ? "true" : "false");
        return os.str();
    }
} // namespace container_image_inventory
