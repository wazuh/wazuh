/*
 * Wazuh agent credential store CLI
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "agent_credential_store.hpp"

#include <homedirHelper.hpp>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace
{
    void usage()
    {
        std::cout
            << "Usage: wazuh-agent-keystore -f <family> -k <key> [-v <value> | -vp <file>]\n"
               "       wazuh-agent-keystore -f <family> -k <key> -d\n"
               "\n"
               "Stores a credential the agent reads at scan time, so the value never has to be\n"
               "written into ossec.conf.\n"
               "\n"
               "  -f <family>   Credential family, e.g. container_images.\n"
               "  -k <key>      Key name, as referenced from the configuration.\n"
               "  -v <value>    The value. Prefer one of the two forms below: an argument is\n"
               "                visible in the shell history and in the process list while this\n"
               "                command runs.\n"
               "  -vp <file>    Read the value from a file.\n"
               "  -d            Remove the key.\n"
               "  -p <path>     Store location. Defaults to the agent's own store.\n"
               "\n"
               "With neither -v, -vp nor -d, the value is read from standard input:\n"
               "  echo \"$TOKEN\" | wazuh-agent-keystore -f container_images -k ghcr_token\n"
               "\n"
               "What this protects: the credential is kept out of ossec.conf, and so out of\n"
               "configuration backups, shared-configuration pushes and support bundles. The\n"
               "file's permissions are what protect it locally. It is not proof against anyone\n"
               "who already has root on this host.\n";
    }

    /// @brief Read a whole stream, dropping one trailing newline.
    ///
    /// The newline matters: `echo` adds one, and a token stored with it is a different
    /// token, which fails authentication for a reason nobody would find.
    std::string readAll(std::istream& input)
    {
        std::ostringstream contents;
        contents << input.rdbuf();

        auto value {contents.str()};

        while (!value.empty() && (value.back() == '\n' || value.back() == '\r'))
        {
            value.pop_back();
        }

        return value;
    }
} // namespace

int main(int argc, char* argv[])
{
    std::string family;
    std::string key;
    std::string value;
    std::string valuePath;
    std::string storePath {containerimages::CREDENTIAL_STORE_PATH};

    auto haveValue {false};
    auto remove {false};

    for (int index = 1; index < argc; ++index)
    {
        const std::string argument {argv[index]};

        const auto next = [&index, argc, argv](std::string& target)
        {
            if (index + 1 >= argc)
            {
                return false;
            }

            target = argv[++index];

            return true;
        };

        if (argument == "-f" && next(family))
        {
            continue;
        }

        if (argument == "-k" && next(key))
        {
            continue;
        }

        if (argument == "-v" && next(value))
        {
            haveValue = true;
            continue;
        }

        if (argument == "-vp" && next(valuePath))
        {
            continue;
        }

        if (argument == "-p" && next(storePath))
        {
            continue;
        }

        if (argument == "-d")
        {
            remove = true;
            continue;
        }

        if (argument == "-h" || argument == "--help")
        {
            usage();
            return 0;
        }

        std::cerr << "Unrecognized argument: " << argument << "\n\n";
        usage();

        return 1;
    }

    if (family.empty() || key.empty())
    {
        std::cerr << "Both -f and -k are required.\n\n";
        usage();

        return 1;
    }

    // The store path is relative to the installation directory, which is what
    // wazuh-modulesd resolves it against because it chdirs there at startup. Without the
    // same step this tool would write the credential relative to wherever it was run
    // from, report success, and leave the agent reporting the credential missing. The
    // manager's own keystore CLI does exactly this for the same reason.
    if (storePath == containerimages::CREDENTIAL_STORE_PATH)
    {
        try
        {
            std::filesystem::current_path(Utils::findHomeDirectory());
        }
        catch (const std::exception& exception)
        {
            std::cerr << "Could not find the Wazuh installation directory: " << exception.what() << "\n";
            return 1;
        }
    }

    const containerimages::AgentCredentialStore store {storePath};

    if (remove)
    {
        if (!store.remove(family, key))
        {
            std::cerr << "No such credential.\n";
            return 1;
        }

        std::cout << "Credential removed.\n";

        return 0;
    }

    if (!valuePath.empty())
    {
        std::ifstream file {valuePath, std::ios::binary};

        if (!file.is_open())
        {
            std::cerr << "Could not read " << valuePath << ".\n";
            return 1;
        }

        value = readAll(file);
    }
    else if (!haveValue)
    {
        // Neither -v nor -vp, so the value comes from standard input, which is the form
        // the documentation leads with: an argument is visible in the shell history and
        // in the process list while the command runs.
        value = readAll(std::cin);
    }

    if (value.empty())
    {
        std::cerr << "The value is empty.\n";
        return 1;
    }

    if (!store.put(family, key, containerimages::Secret {value}))
    {
        // put() has already reported why through the module's logging helper.
        std::cerr << "The credential was not stored.\n";
        return 1;
    }

    std::cout << "Credential stored in " << store.path() << ".\n";

    return 0;
}
