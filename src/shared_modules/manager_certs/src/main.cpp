/*
 * wazuh-manager-certs: inspect and check the CA bundle the manager's HTTPS listener serves.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of GPLv2.
 */

#include "manager_certs/commands.hpp"

#include <ca_bundle/ca_bundle.hpp>
#include <manager_config/manager_config.hpp>

#include <rapidjson/document.h>
#include <rapidjson/pointer.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#ifndef WAZUH_MANAGER_CERTS_VERSION
#define WAZUH_MANAGER_CERTS_VERSION "unknown"
#endif

namespace
{
    constexpr int EXIT_OK = 0;          ///< Command ran; the bundle is vouched for (`check`).
    constexpr int EXIT_REJECTED = 1;    ///< `inspect`/`check` refused it, or a usage error.
    constexpr int EXIT_ENVIRONMENT = 2; ///< Configuration, bundle or leaf could not be read.

    /// Same variable w_homedir() honours for the manager (defs.h WAZUH_HOME_ENV).
    constexpr const char* HOME_ENV = "WAZUH_MANAGER_HOME";
    constexpr const char* DEFAULT_FILE = "etc/wazuh-manager.conf";

    void usage(std::FILE* out)
    {
        std::fputs("Usage: wazuh-manager-certs [-f <file>] [-H <home>] <command>\n"
                   "\n"
                   "Commands:\n"
                   "  inspect             Describe the CA bundle's certificates and publication status.\n"
                   "  check               Validate the CA bundle without writing anything.\n"
                   "\n"
                   "Options:\n"
                   "  -f <file>           Configuration file (default: <home>/etc/wazuh-manager.conf).\n"
                   "  -H <home>           Manager home used to resolve relative paths (default: $WAZUH_MANAGER_HOME,\n"
                   "                      else the parent of the bin/ directory holding this program).\n"
                   "  -h, --help          This help.\n"
                   "  -V, --version       Print the version.\n"
                   "\n"
                   "-h/--help and -V/--version never read the configuration: they work with every daemon\n"
                   "stopped and without a manager home set.\n"
                   "\n"
                   "'add', 'remove', 'prune-expired', 'stamp' and '--from-master' arrive in later versions.\n"
                   "\n"
                   "Exit status: 0 success; 1 the bundle was rejected, or a usage error; 2 environment error\n"
                   "(configuration, bundle or leaf could not be read).\n",
                   out);
    }

    int usageError(const std::string& message)
    {
        std::fprintf(stderr, "wazuh-manager-certs: %s\n", message.c_str());
        usage(stderr);
        return EXIT_REJECTED;
    }

    int environmentError(const std::string& message)
    {
        std::fprintf(stderr, "wazuh-manager-certs: %s\n", message.c_str());
        return EXIT_ENVIRONMENT;
    }

    /// -H, then $WAZUH_MANAGER_HOME, then the parent of this binary's bin/ directory (as w_homedir()).
    /// Exact mold of manager_config/cli/manager-conf.cpp's resolveHome(): same fallback chain, same
    /// $WAZUH_MANAGER_HOME, so both CLIs resolve a bare relative configuration path identically.
    std::filesystem::path resolveHome(const std::string& fromOption)
    {
        if (!fromOption.empty())
        {
            return fromOption;
        }
        if (const char* env = std::getenv(HOME_ENV); env != nullptr && *env != '\0')
        {
            return env;
        }
        std::error_code ec;
        const auto exe = std::filesystem::read_symlink("/proc/self/exe", ec);
        if (!ec && exe.has_parent_path())
        {
            return exe.parent_path().parent_path();
        }
        return std::filesystem::current_path(ec);
    }

    /// @p path resolved against @p home when it is not already absolute.
    std::filesystem::path resolvePath(const std::string& path, const std::filesystem::path& home)
    {
        std::filesystem::path candidate {path};
        return candidate.is_absolute() ? candidate : home / candidate;
    }

    /// The string at @p pointer in @p document, or an empty string when absent or not a string.
    std::string stringAt(const rapidjson::Document& document, const char* pointer)
    {
        const rapidjson::Value* value = rapidjson::Pointer(pointer).Get(document);
        return (value != nullptr && value->IsString()) ? value->GetString() : std::string {};
    }

    /// The whole content of @p path, or nullopt when it cannot be opened for reading.
    std::optional<std::string> readWholeFile(const std::filesystem::path& path)
    {
        std::ifstream file {path, std::ios::binary};
        if (!file)
        {
            return std::nullopt;
        }
        std::ostringstream buffer;
        buffer << file.rdbuf();
        if (file.bad())
        {
            return std::nullopt;
        }
        return buffer.str();
    }

    /// The leaf certificate at @p path, read directly with OpenSSL (C15: the leaf the listener will
    /// serve on its next start, from disk -- not from a running daemon, which may not even be up).
    /// nullptr when the file cannot be opened or does not parse as a single certificate.
    ca_bundle::X509Ptr readLeaf(const std::filesystem::path& path)
    {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio {BIO_new_file(path.c_str(), "r"), &BIO_free};
        if (!bio)
        {
            ERR_clear_error();
            return {};
        }
        ca_bundle::X509Ptr leaf {PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
        if (!leaf)
        {
            ERR_clear_error();
        }
        return leaf;
    }

    int run(int argc, char** argv)
    {
        std::string file;
        std::string home;
        std::vector<std::string> positional;

        for (int i = 1; i < argc; ++i)
        {
            const std::string_view arg = argv[i];
            if (arg == "-h" || arg == "--help")
            {
                usage(stdout);
                return EXIT_OK;
            }
            if (arg == "-V" || arg == "--version")
            {
                std::printf("wazuh-manager-certs %s\n", WAZUH_MANAGER_CERTS_VERSION);
                return EXIT_OK;
            }
            if (arg == "-f" || arg == "-H")
            {
                if (i + 1 >= argc)
                {
                    return usageError(std::string(arg) + " needs an argument");
                }
                (arg == "-f" ? file : home) = argv[++i];
            }
            else if (arg.size() > 1 && arg[0] == '-')
            {
                return usageError("unknown option '" + std::string(arg) + "'");
            }
            else
            {
                positional.emplace_back(arg);
            }
        }

        if (positional.empty())
        {
            return usageError("missing command");
        }
        const std::string& command = positional[0];
        if (command != "inspect" && command != "check")
        {
            return usageError("'" + command + "' is not available yet (it arrives in a later version)");
        }
        if (positional.size() != 1)
        {
            return usageError("'" + command + "' takes no arguments");
        }

        const std::filesystem::path homePath = resolveHome(home);
        const std::filesystem::path filePath = file.empty() ? homePath / DEFAULT_FILE : std::filesystem::path(file);
        std::error_code ec;
        if (!std::filesystem::is_regular_file(filePath, ec))
        {
            return environmentError("configuration file not found: " + filePath.string());
        }

        // File-existence checks are ours to do (bundle/leaf get their own, distinct messages below):
        // manager_config's own checkFiles never looks at /remote/https/ca_certificate at all, and
        // folding /remote/https/certificate's check into it would collapse "leaf missing" into
        // "configuration invalid".
        manager_config::LoadOptions options;
        options.checkFiles = false;
        options.home = homePath;
        auto loaded = manager_config::Document::load(filePath, options);
        if (const auto* error = std::get_if<manager_config::Error>(&loaded))
        {
            return environmentError("configuration is invalid: " + error->what());
        }
        const auto& document = std::get<manager_config::Document>(loaded);

        rapidjson::Document json;
        json.Parse(document.documentJson().c_str());
        if (json.HasParseError())
        {
            return environmentError("internal error: the effective configuration is not valid JSON");
        }

        const std::string bundlePathString = stringAt(json, "/remote/https/ca_certificate");
        const std::string leafPathString = stringAt(json, "/remote/https/certificate");
        if (bundlePathString.empty())
        {
            return environmentError("the effective configuration does not set /remote/https/ca_certificate");
        }
        if (leafPathString.empty())
        {
            return environmentError("the effective configuration does not set /remote/https/certificate");
        }
        const std::filesystem::path bundlePath = resolvePath(bundlePathString, homePath);
        const std::filesystem::path leafPath = resolvePath(leafPathString, homePath);

        const auto bundleContent = readWholeFile(bundlePath);
        if (!bundleContent)
        {
            return environmentError("CA bundle not found or not readable: " + bundlePath.string());
        }

        ca_bundle::X509Ptr leaf = readLeaf(leafPath);
        if (!leaf)
        {
            return environmentError("leaf certificate not found or not readable: " + leafPath.string());
        }

        const ca_bundle::ParsedBundle bundle = ca_bundle::parseBundle(*bundleContent);

        if (command == "inspect")
        {
            return manager_certs::runInspect(bundle, leaf.get(), std::cout);
        }
        // command == "check"
        const auto serializedBytes = ca_bundle::serializeCertificates(bundle.certificates).size();
        return manager_certs::runCheck(bundle, leaf.get(), serializedBytes, std::cerr);
    }
} // namespace

int main(int argc, char** argv)
{
    try
    {
        return run(argc, argv);
    }
    catch (const std::exception& e)
    {
        std::fprintf(stderr, "wazuh-manager-certs: %s\n", e.what());
        return EXIT_ENVIRONMENT;
    }
}
