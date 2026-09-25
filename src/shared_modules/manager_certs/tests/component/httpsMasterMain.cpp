/*
 * Wazuh manager certs tool - the component test's HTTPS master, as a program
 * Copyright (C) 2015, Wazuh Inc.
 * September 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// The one thing testHttpsMaster.hpp cannot be on its own: a process the shell script starts and
// kills. Nothing but argument parsing lives here -- the server, and every response shape the
// component test needs, is the header's.

#include "testHttpsMaster.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

namespace
{
    void usage()
    {
        std::fputs("Usage: manager_certs_test_master --port <n> --cert <pem> --key <pem> [options]\n"
                   "\n"
                   "  --port <n>           0 (the usual case) binds any free port.\n"
                   "  --bind <address>     Listen address (default 127.0.0.1).\n"
                   "  --body <file>        PEM to serve as the body.\n"
                   "  --generation <value> Wazuh-CA-Generation header; omitted when not given.\n"
                   "  --status <n>         HTTP status (default 200).\n"
                   "  --pad-to <bytes>     Pad the body with comment lines to exactly <bytes>.\n"
                   "  --chunks <n>         Serve the body in <n> chunked pieces.\n"
                   "  --truncate           Promise more body than is sent, then drop the connection.\n"
                   "  --request-log <file> Append every requested path here.\n"
                   "  --ready-file <file>  Created once the socket is bound.\n",
                   stderr);
    }
} // namespace

int main(int argc, char** argv)
{
    manager_certs::test::HttpsMasterOptions options;

    for (int index = 1; index < argc; ++index)
    {
        const std::string argument = argv[index];
        const auto next = [&]() -> std::string
        {
            if (index + 1 >= argc)
            {
                usage();
                std::exit(2);
            }
            return argv[++index];
        };

        if (argument == "--port")
        {
            options.port = std::atoi(next().c_str());
        }
        else if (argument == "--cert")
        {
            options.certificatePath = next();
        }
        else if (argument == "--key")
        {
            options.privateKeyPath = next();
        }
        else if (argument == "--bind")
        {
            options.bindAddress = next();
        }
        else if (argument == "--body")
        {
            options.bodyPath = next();
        }
        else if (argument == "--generation")
        {
            options.generation = next();
        }
        else if (argument == "--status")
        {
            options.status = std::atoi(next().c_str());
        }
        else if (argument == "--pad-to")
        {
            options.padTo = static_cast<std::size_t>(std::strtoull(next().c_str(), nullptr, 10));
        }
        else if (argument == "--chunks")
        {
            options.chunks = static_cast<std::size_t>(std::strtoull(next().c_str(), nullptr, 10));
        }
        else if (argument == "--truncate")
        {
            options.truncate = true;
        }
        else if (argument == "--request-log")
        {
            options.requestLog = next();
        }
        else if (argument == "--ready-file")
        {
            options.readyFile = next();
        }
        else
        {
            usage();
            return 2;
        }
    }

    // Port 0 is the usual case, not an error: it means "any free one", and the bound port is
    // written to the ready file for the script to read.
    if (options.port < 0 || options.certificatePath.empty() || options.privateKeyPath.empty())
    {
        usage();
        return 2;
    }

    return manager_certs::test::runHttpsMaster(options);
}
