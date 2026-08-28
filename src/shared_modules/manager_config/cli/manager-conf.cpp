/*
 * wazuh-manager-conf: validate, query and dump the manager configuration (etc/wazuh-manager.yml).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of GPLv2.
 */

#include <manager_config/manager_config.hpp>

#include <rapidjson/document.h>
#include <rapidjson/pointer.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "error_messages.h"

#ifndef WAZUH_MANAGER_CONF_VERSION
#define WAZUH_MANAGER_CONF_VERSION "unknown"
#endif

namespace
{
    constexpr int EXIT_INVALID = 1; ///< Invalid configuration, missing file or usage error.
    constexpr int EXIT_NOT_SET = 2; ///< `get` of a key absent from the effective document.

    /// Same variable w_homedir() honours for the manager (defs.h WAZUH_HOME_ENV).
    constexpr const char* HOME_ENV = "WAZUH_MANAGER_HOME";
    constexpr const char* DEFAULT_FILE = "etc/wazuh-manager.yml";

    void usage(std::FILE* out)
    {
        std::fputs("Usage: wazuh-manager-conf [-f <file>] [-H <home>] [--skip-file-checks] <command>\n"
                   "\n"
                   "Commands:\n"
                   "  validate            Check the file (YAML, schema and cross-field rules); silent on success.\n"
                   "  get <key.path>      Print one option of the effective configuration (defaults applied):\n"
                   "                      scalars as plain text, objects and lists as JSON.\n"
                   "  dump                Print the whole effective configuration as JSON.\n"
                   "\n"
                   "Options:\n"
                   "  -f <file>           Configuration file (default: <home>/etc/wazuh-manager.yml).\n"
                   "  -H <home>           Manager home used to resolve relative paths (default: $WAZUH_MANAGER_HOME,\n"
                   "                      else the parent of the bin/ directory holding this program).\n"
                   "  --skip-file-checks  Do not require the certificate/key files named in the file to exist.\n"
                   "  -h, --help          This help.\n"
                   "  -V, --version       Print the version.\n"
                   "\n"
                   "Exit status: 0 success; 1 invalid configuration, missing file or usage error; 2 key not set.\n",
                   out);
    }

    int usageError(const std::string& message)
    {
        std::fprintf(stderr, "wazuh-manager-conf: %s\n", message.c_str());
        usage(stderr);
        return EXIT_INVALID;
    }

    /// -H, then $WAZUH_MANAGER_HOME, then the parent of this binary's bin/ directory (as w_homedir()).
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

    /// `a.b.c` -> `/a/b/c` (RFC 6901 escaping of `~` and `/` inside a segment).
    std::string toJsonPointer(std::string_view dotted)
    {
        std::string pointer;
        std::string segment;
        const auto flush = [&]()
        {
            pointer += '/';
            pointer += segment;
            segment.clear();
        };
        for (const char c : dotted)
        {
            if (c == '.')
            {
                flush();
            }
            else if (c == '~')
            {
                segment += "~0";
            }
            else if (c == '/')
            {
                segment += "~1";
            }
            else
            {
                segment += c;
            }
        }
        flush();
        return pointer;
    }

    template<typename Writer>
    std::string toJson(const rapidjson::Value& value)
    {
        rapidjson::StringBuffer buffer;
        Writer writer(buffer);
        value.Accept(writer);
        return buffer.GetString();
    }

    /// Scalars in plain text (strings unquoted), everything else as compact JSON.
    void printValue(const rapidjson::Value& value)
    {
        if (value.IsString())
        {
            std::printf("%s\n", value.GetString());
        }
        else if (value.IsBool())
        {
            std::puts(value.GetBool() ? "true" : "false");
        }
        else if (value.IsNull())
        {
            std::puts("null");
        }
        else
        {
            std::printf("%s\n", toJson<rapidjson::Writer<rapidjson::StringBuffer>>(value).c_str());
        }
    }

    int reportInvalid(const manager_config::Error& error)
    {
        const std::string pointer = error.pointer.empty() ? "/" : error.pointer;
        std::fprintf(stderr, CONFIG_YAML_INVALID "\n", pointer.c_str(), error.message.c_str());
        return EXIT_INVALID;
    }

    int run(int argc, char** argv)
    {
        std::string file;
        std::string home;
        bool skipFileChecks = false;
        std::vector<std::string> positional;

        for (int i = 1; i < argc; ++i)
        {
            const std::string_view arg = argv[i];
            if (arg == "-h" || arg == "--help")
            {
                usage(stdout);
                return 0;
            }
            if (arg == "-V" || arg == "--version")
            {
                std::printf("wazuh-manager-conf %s\n", WAZUH_MANAGER_CONF_VERSION);
                return 0;
            }
            if (arg == "--skip-file-checks")
            {
                skipFileChecks = true;
            }
            else if (arg == "-f" || arg == "-H")
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
        std::string key;
        if (command == "get")
        {
            if (positional.size() != 2)
            {
                return usageError("'get' takes exactly one key (e.g. cluster.node_type)");
            }
            key = positional[1];
        }
        else if (command == "validate" || command == "dump")
        {
            if (positional.size() != 1)
            {
                return usageError("'" + command + "' takes no arguments");
            }
        }
        else
        {
            return usageError("unknown command '" + command + "'");
        }

        const std::filesystem::path homePath = resolveHome(home);
        const std::filesystem::path filePath = file.empty() ? homePath / DEFAULT_FILE : std::filesystem::path(file);
        std::error_code ec;
        if (!std::filesystem::is_regular_file(filePath, ec))
        {
            std::fprintf(stderr, NO_CONFIG "\n", filePath.c_str());
            return EXIT_INVALID;
        }

        manager_config::LoadOptions options;
        options.checkFiles = !skipFileChecks;
        options.home = homePath;

        if (command == "validate")
        {
            if (const auto error = manager_config::validateFile(filePath, options))
            {
                return reportInvalid(*error);
            }
            return 0;
        }

        auto loaded = manager_config::Document::load(filePath, options);
        if (const auto* error = std::get_if<manager_config::Error>(&loaded))
        {
            return reportInvalid(*error);
        }
        const auto& document = std::get<manager_config::Document>(loaded);

        rapidjson::Document json;
        json.Parse(document.documentJson().c_str());
        if (json.HasParseError())
        {
            std::fputs("wazuh-manager-conf: internal error: the effective document is not valid JSON\n", stderr);
            return EXIT_INVALID;
        }

        if (command == "dump")
        {
            std::printf("%s\n", toJson<rapidjson::PrettyWriter<rapidjson::StringBuffer>>(json).c_str());
            return 0;
        }

        const rapidjson::Pointer pointer(toJsonPointer(key).c_str());
        const rapidjson::Value* value = pointer.IsValid() ? pointer.Get(json) : nullptr;
        if (value == nullptr)
        {
            std::fprintf(stderr, "wazuh-manager-conf: '%s' is not set\n", key.c_str());
            return EXIT_NOT_SET;
        }
        printValue(*value);
        return 0;
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
        std::fprintf(stderr, "wazuh-manager-conf: %s\n", e.what());
        return EXIT_INVALID;
    }
}
