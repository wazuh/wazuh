/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "containerImageInventory.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <unordered_set>
#include <unistd.h>

#include "imageArchiveParser.hpp"
#include "overlayFsResolver.hpp"
#include "packageDbExtractor.hpp"
#include "packageInventoryScanner.hpp"

namespace container_image_inventory
{
    Scanner::Scanner(TraceFn trace)
        : m_trace(std::move(trace))
    {
    }

    void Scanner::trace(const std::string& msg) const
    {
        if (m_trace)
        {
            m_trace(msg);
        }
    }

    ScanResult Scanner::scan_archive(const ScanOptions& opts)
    {
        const auto t0 = std::chrono::steady_clock::now();
        ScanResult r;
        r.source_type = "archive";
        r.source_path = opts.archive_path;
        r.configured_ref = opts.configured_ref;

        trace("scan started source=archive path=" + opts.archive_path + " ref=" + opts.configured_ref);

        ImageArchiveParser parser(m_trace);
        if (!parser.load(opts.archive_path))
        {
            throw std::runtime_error("failed to open archive: " + opts.archive_path);
        }

        const auto entry = parser.read_manifest();
        r.image = parser.read_image_config(entry);
        trace("layers discovered count=" + std::to_string(entry.layers.size()));

        const auto candidates = candidate_db_paths();
        std::unordered_set<std::string> wanted;
        for (const auto& c : candidates)
        {
            wanted.insert(c.path);
        }
        trace("probing package database candidates count=" + std::to_string(wanted.size()));

        ArchiveBlobProvider provider(parser);
        OverlayFsResolver resolver(m_trace);
        const auto vfs = resolver.resolve(provider, entry.layers, wanted);

        auto sel = pick_database(provider, vfs, m_trace);
        if (sel.backend == PackageBackend::None)
        {
            r.package_manager = "none";
            r.database_path.clear();
            const auto t1 = std::chrono::steady_clock::now();
            r.elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
            trace("no package database detected — distroless or unsupported");
            trace("scan completed elapsed_ms=" + std::to_string(r.elapsed_ms));
            return r;
        }

        r.database_path = sel.database_path;

        switch (sel.backend)
        {
            case PackageBackend::Dpkg:
            {
                r.package_manager = "dpkg";
                std::string content(reinterpret_cast<const char*>(sel.bytes.data()), sel.bytes.size());
                r.packages = parse_dpkg(content);
                break;
            }
            case PackageBackend::Apk:
            {
                r.package_manager = "apk";
                std::string content(reinterpret_cast<const char*>(sel.bytes.data()), sel.bytes.size());
                r.packages = parse_apk(content);
                break;
            }
            case PackageBackend::RpmSqlite:
            {
                r.package_manager = "rpm";
                r.rpm_backend = "sqlite";
                std::string tmp = write_temp_file(sel.bytes, ".sqlite");
                try
                {
                    r.packages = parse_rpm_sqlite(tmp);
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
                r.package_manager = "rpm";
                r.rpm_backend = "bdb";
                std::string tmp = write_temp_file(sel.bytes, ".Packages");
                try
                {
                    r.packages = parse_rpm_bdb(tmp);
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
                r.package_manager = "rpm";
                r.rpm_backend = "ndb-unsupported";
                trace("RPM NDB detected — backend not implemented in PoC, returning zero packages");
                break;
            }
            default:
                break;
        }

        r.package_count = static_cast<int>(r.packages.size());
        trace("packages parsed count=" + std::to_string(r.package_count));

        const auto t1 = std::chrono::steady_clock::now();
        r.elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        trace("scan completed elapsed_ms=" + std::to_string(r.elapsed_ms));
        return r;
    }

    nlohmann::json result_to_json(const ScanResult& r)
    {
        nlohmann::json j;
        j["source"] = {
            {"type", r.source_type},
            {"path", r.source_path},
            {"configured_ref", r.configured_ref},
        };

        nlohmann::json img;
        img["repo_tags"] = r.image.repo_tags;
        img["os"] = r.image.os;
        img["architecture"] = r.image.architecture;
        img["image_id"] = r.image.image_id;
        img["config_digest"] = r.image.config_digest;
        if (r.image.manifest_digest.has_value())
        {
            img["manifest_digest"] = *r.image.manifest_digest;
        }
        else
        {
            img["manifest_digest"] = nullptr;
        }
        img["layer_count"] = r.image.layer_count;
        j["image"] = img;

        nlohmann::json scan;
        scan["package_manager"] = r.package_manager;
        if (r.rpm_backend.has_value())
        {
            scan["rpm_backend"] = *r.rpm_backend;
        }
        else
        {
            scan["rpm_backend"] = nullptr;
        }
        scan["database_path"] = r.database_path;
        scan["package_count"] = r.package_count;
        scan["elapsed_ms"] = r.elapsed_ms;
        j["scan"] = scan;

        nlohmann::json pkgs = nlohmann::json::array();
        for (const auto& p : r.packages)
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

    std::string result_to_summary(const ScanResult& r)
    {
        std::string rpm_be = r.rpm_backend.has_value() ? *r.rpm_backend : std::string("null");
        std::ostringstream os;
        os << "source=" << r.source_type
           << " ref=" << (r.configured_ref.empty() ? std::string("-") : r.configured_ref)
           << " os=" << r.image.os
           << " arch=" << r.image.architecture
           << " pm=" << r.package_manager
           << " rpm_backend=" << rpm_be
           << " db=" << (r.database_path.empty() ? std::string("-") : r.database_path)
           << " count=" << r.package_count;
        return os.str();
    }
} // namespace container_image_inventory
