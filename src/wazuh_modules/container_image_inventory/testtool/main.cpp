/*
 * Wazuh container image inventory PoC - test tool / CLI
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#include "containerImageInventory.hpp"
#include "imageReference.hpp"
#include "remoteImageScanner.hpp"

namespace
{
    using namespace container_image_inventory;

    constexpr const char* DEFAULT_CACHE_DIR = "/tmp/wazuh-container-image-inventory-cache";

    struct CliOptions
    {
        std::string archive;
        std::string image;
        std::string ref;
        std::string platform;
        std::string output_json;
        std::string config;
        std::string cache_dir;
        std::string username;
        std::string password;
        std::string bearer_token;
        bool summary{false};
        bool trace{false};
        bool no_cache{false};
        bool no_blob_cache{false};
        bool help{false};
    };

    void usage(std::ostream& os)
    {
        os << "Usage:\n"
           << "  container-image-inventory-poc --archive <docker-save-tar>\n"
           << "        [--ref <image-ref>] [--output-json <path>] [--summary] [--trace]\n"
           << "\n"
           << "  container-image-inventory-poc --image <remote-ref>\n"
           << "        [--platform <os/arch[/variant]>] [--cache-dir <path>]\n"
           << "        [--username <user>] [--password <pwd-or-token>] [--bearer-token <token>]\n"
           << "        [--no-cache] [--no-blob-cache]\n"
           << "        [--output-json <path>] [--summary] [--trace]\n"
           << "\n"
           << "  container-image-inventory-poc --config <ossec.conf>\n"
           << "        [--cache-dir <path>] [--summary] [--trace]\n";
    }

    bool parse_cli(int argc, char** argv, CliOptions& opts)
    {
        auto need_arg = [&](int& i, const char* flag) {
            if (i + 1 >= argc)
            {
                std::cerr << "ERROR: " << flag << " requires a value\n";
                return false;
            }
            return true;
        };
        for (int i = 1; i < argc; ++i)
        {
            std::string a = argv[i];
            if (a == "--archive")
            {
                if (!need_arg(i, "--archive")) return false;
                opts.archive = argv[++i];
            }
            else if (a == "--image")
            {
                if (!need_arg(i, "--image")) return false;
                opts.image = argv[++i];
            }
            else if (a == "--ref")
            {
                if (!need_arg(i, "--ref")) return false;
                opts.ref = argv[++i];
            }
            else if (a == "--platform")
            {
                if (!need_arg(i, "--platform")) return false;
                opts.platform = argv[++i];
            }
            else if (a == "--output-json")
            {
                if (!need_arg(i, "--output-json")) return false;
                opts.output_json = argv[++i];
            }
            else if (a == "--config")
            {
                if (!need_arg(i, "--config")) return false;
                opts.config = argv[++i];
            }
            else if (a == "--cache-dir")
            {
                if (!need_arg(i, "--cache-dir")) return false;
                opts.cache_dir = argv[++i];
            }
            else if (a == "--username")
            {
                if (!need_arg(i, "--username")) return false;
                opts.username = argv[++i];
            }
            else if (a == "--password")
            {
                if (!need_arg(i, "--password")) return false;
                opts.password = argv[++i];
            }
            else if (a == "--bearer-token")
            {
                if (!need_arg(i, "--bearer-token")) return false;
                opts.bearer_token = argv[++i];
            }
            else if (a == "--summary")
            {
                opts.summary = true;
            }
            else if (a == "--trace")
            {
                opts.trace = true;
            }
            else if (a == "--no-cache")
            {
                opts.no_cache = true;
            }
            else if (a == "--no-blob-cache")
            {
                opts.no_blob_cache = true;
            }
            else if (a == "--help" || a == "-h")
            {
                opts.help = true;
            }
            else
            {
                std::cerr << "ERROR: unknown argument: " << a << "\n";
                return false;
            }
        }
        return true;
    }

    void emit_archive_result(const ScanResult& r, const CliOptions& opts)
    {
        if (!opts.output_json.empty())
        {
            std::ofstream f(opts.output_json);
            if (!f)
            {
                std::cerr << "ERROR: cannot write " << opts.output_json << "\n";
            }
            else
            {
                f << result_to_json(r).dump(2);
            }
        }
        if (opts.summary)
        {
            std::cout << result_to_summary(r) << "\n";
        }
        else if (opts.output_json.empty())
        {
            std::cout << result_to_json(r).dump(2) << "\n";
        }
    }

    void emit_remote_result(const RemoteScanResult& r, const CliOptions& opts)
    {
        if (!opts.output_json.empty())
        {
            std::ofstream f(opts.output_json);
            if (!f)
            {
                std::cerr << "ERROR: cannot write " << opts.output_json << "\n";
            }
            else
            {
                f << remote_result_to_json(r).dump(2);
            }
        }
        if (opts.summary)
        {
            std::cout << remote_result_to_summary(r) << "\n";
        }
        else if (opts.output_json.empty())
        {
            std::cout << remote_result_to_json(r).dump(2) << "\n";
        }
    }

    // -------------------------------------------------------------------
    // Minimal config reader: extract every <image> entry under
    // <wodle name="container-image-inventory">. Tolerant of formatting,
    // intentionally not a full XML parser — sufficient for PoC ossec.conf.
    // -------------------------------------------------------------------

    struct ConfImage
    {
        std::string type;
        std::string path;
        std::string ref;
        std::string platform;
        std::string username;
        std::string password;
        std::string bearer_token;
    };

    struct ConfWodle
    {
        std::string cache_dir;
        std::vector<ConfImage> images;
    };

    std::string read_file(const std::string& path)
    {
        std::ifstream f(path);
        std::stringstream ss;
        ss << f.rdbuf();
        return ss.str();
    }

    // Replace ${VAR} with environment value, leave as-is if not set.
    std::string expand_env(const std::string& in)
    {
        std::string out;
        out.reserve(in.size());
        for (size_t i = 0; i < in.size();)
        {
            if (in[i] == '$' && i + 1 < in.size() && in[i + 1] == '{')
            {
                const auto end = in.find('}', i + 2);
                if (end == std::string::npos)
                {
                    out.push_back(in[i++]);
                    continue;
                }
                const auto name = in.substr(i + 2, end - i - 2);
                const char* val = std::getenv(name.c_str());
                if (val)
                {
                    out += val;
                }
                else
                {
                    out += in.substr(i, end - i + 1);
                }
                i = end + 1;
            }
            else
            {
                out.push_back(in[i++]);
            }
        }
        return out;
    }

    std::string extract_tag(const std::string& block, const std::string& tag)
    {
        const std::regex re("<" + tag + ">\\s*([^<]*)\\s*</" + tag + ">", std::regex::icase);
        std::smatch m;
        if (std::regex_search(block, m, re))
        {
            return expand_env(m[1].str());
        }
        return "";
    }

    ConfWodle parse_conf(const std::string& xml)
    {
        ConfWodle out;
        const std::regex wodle_re(
            "<wodle\\s+name\\s*=\\s*\"container-image-inventory\"\\s*>([\\s\\S]*?)</wodle>",
            std::regex::icase);
        std::smatch w;
        auto begin = xml.cbegin();
        const auto end = xml.cend();
        while (std::regex_search(begin, end, w, wodle_re))
        {
            const std::string body = w[1].str();
            if (out.cache_dir.empty())
            {
                out.cache_dir = extract_tag(body, "cache_dir");
            }
            const std::regex img_re("<image>([\\s\\S]*?)</image>", std::regex::icase);
            std::smatch m;
            auto bb = body.cbegin();
            const auto be = body.cend();
            while (std::regex_search(bb, be, m, img_re))
            {
                const std::string blk = m[1].str();
                ConfImage ci;
                ci.type = extract_tag(blk, "type");
                ci.path = extract_tag(blk, "path");
                ci.ref = extract_tag(blk, "ref");
                ci.platform = extract_tag(blk, "platform");
                ci.username = extract_tag(blk, "username");
                ci.password = extract_tag(blk, "password");
                ci.bearer_token = extract_tag(blk, "bearer_token");
                if (!ci.type.empty())
                {
                    out.images.push_back(std::move(ci));
                }
                bb = m.suffix().first;
            }
            begin = w.suffix().first;
        }
        return out;
    }
} // namespace

int main(int argc, char** argv)
{
    CliOptions opts;
    if (!parse_cli(argc, argv, opts))
    {
        usage(std::cerr);
        return 2;
    }
    if (opts.help || (opts.archive.empty() && opts.image.empty() && opts.config.empty()))
    {
        usage(std::cout);
        return opts.help ? 0 : 2;
    }

    TraceFn trace = nullptr;
    if (opts.trace)
    {
        trace = [](const std::string& m) {
            std::cerr << "container-image-inventory: " << m << "\n";
        };
    }

    const std::string cache_dir =
        opts.cache_dir.empty() ? std::string(DEFAULT_CACHE_DIR) : opts.cache_dir;

    try
    {
        if (!opts.archive.empty() && !opts.image.empty())
        {
            std::cerr << "ERROR: --archive and --image are mutually exclusive\n";
            return 2;
        }
        if (!opts.archive.empty())
        {
            Scanner scanner(trace);
            ScanOptions so;
            so.archive_path = opts.archive;
            so.configured_ref = opts.ref;
            const auto r = scanner.scan_archive(so);
            emit_archive_result(r, opts);
            return 0;
        }
        if (!opts.image.empty())
        {
            RemoteImageScanner scanner(trace);
            RemoteScanOptions ro;
            ro.image_ref = opts.image;
            ro.platform = opts.platform;
            ro.auth.username = opts.username;
            ro.auth.password = opts.password;
            ro.auth.bearer_token = opts.bearer_token;
            ro.cache_dir = cache_dir;
            ro.use_result_cache = !opts.no_cache;
            ro.use_blob_cache = !opts.no_blob_cache;
            const auto r = scanner.scan(ro);
            emit_remote_result(r, opts);
            return 0;
        }

        // --config mode
        const auto xml = read_file(opts.config);
        if (xml.empty())
        {
            std::cerr << "ERROR: cannot read config: " << opts.config << "\n";
            return 1;
        }
        const auto wodle = parse_conf(xml);
        const std::string conf_cache_dir =
            !opts.cache_dir.empty() ? opts.cache_dir :
            !wodle.cache_dir.empty() ? wodle.cache_dir : std::string(DEFAULT_CACHE_DIR);
        if (wodle.images.empty())
        {
            std::cerr << "ERROR: no <image> entries found under "
                      << "<wodle name=\"container-image-inventory\">\n";
            return 1;
        }
        Scanner archive_scanner(trace);
        RemoteImageScanner remote_scanner(trace);
        bool any_failed = false;
        nlohmann::json all = nlohmann::json::array();
        for (const auto& ci : wodle.images)
        {
            try
            {
                if (ci.type == "archive")
                {
                    ScanOptions so;
                    so.archive_path = ci.path;
                    so.configured_ref = ci.ref;
                    const auto r = archive_scanner.scan_archive(so);
                    if (opts.summary)
                    {
                        std::cout << result_to_summary(r) << "\n";
                    }
                    else
                    {
                        all.push_back(result_to_json(r));
                    }
                }
                else if (ci.type == "remote")
                {
                    RemoteScanOptions ro;
                    ro.image_ref = ci.ref;
                    ro.platform = ci.platform;
                    ro.auth.username = ci.username;
                    ro.auth.password = ci.password;
                    ro.auth.bearer_token = ci.bearer_token;
                    ro.cache_dir = conf_cache_dir;
                    ro.use_result_cache = !opts.no_cache;
                    ro.use_blob_cache = !opts.no_blob_cache;
                    const auto r = remote_scanner.scan(ro);
                    if (opts.summary)
                    {
                        std::cout << remote_result_to_summary(r) << "\n";
                    }
                    else
                    {
                        all.push_back(remote_result_to_json(r));
                    }
                }
                else
                {
                    std::cerr << "skip: unknown <type>=" << ci.type << "\n";
                }
            }
            catch (const std::exception& e)
            {
                std::cerr << "scan failed type=" << ci.type
                          << " ref=" << (ci.ref.empty() ? ci.path : ci.ref)
                          << " error=" << e.what() << "\n";
                any_failed = true;
            }
        }
        if (!opts.summary)
        {
            if (!opts.output_json.empty())
            {
                std::ofstream f(opts.output_json);
                if (!f)
                {
                    std::cerr << "ERROR: cannot write " << opts.output_json << "\n";
                }
                else
                {
                    f << all.dump(2);
                }
            }
            else
            {
                std::cout << all.dump(2) << "\n";
            }
        }
        return any_failed ? 3 : 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }
}
