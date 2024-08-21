/*
 * Wazuh Vulnerability scanner
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "argsParser.hpp"
#include "base/logging.hpp"
#include "scanOrchestrator.hpp"
#include <exception>
#include <httplib.h>

int main(const int argc, const char* argv[])
{
    try
    {
        CmdLineArgs args(argc, argv);
        logging::start({args.getLogFilePath(), logging::Level::Debug});

        std::string configurationData;
        std::ifstream file(args.getConfigurationFilePath());

        if (file.is_open())
        {
            std::string line;
            while (std::getline(file, line))
            {
                configurationData += line;
            }
            file.close();
        }
        else
        {
            throw std::runtime_error("Error: Unable to open configuration file.");
        }

        ScanOrchestrator scanOrchestrator(configurationData);

        httplib::Server svr;

        svr.Post("/v1/vulnerabilityscanner",
                 [&](const httplib::Request& req, httplib::Response& res)
                 {
                     std::string response;
                     scanOrchestrator.processEvent(req.body, response);
                     res.set_content(response, "application/json");
                 });

        svr.set_error_handler(
            [](const auto&, auto& res)
            {
                nlohmann::json response;
                response["error"] = "Invalid request";
                response["code"] = res.status;
                res.set_content(response.dump(), "application/json");
            });

        svr.set_logger(
            [](const auto& req, const auto& res)
            { LOG_DEBUG("Method: {} - Request: {} - Response status: {}", req.method, req.body, res.status); });

        svr.set_address_family(AF_UNIX);

        if (std::filesystem::exists(args.getSocketPath()))
        {
            std::filesystem::remove(args.getSocketPath());
        }

        svr.listen(args.getSocketPath(), true);
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        CmdLineArgs::showHelp();
        return 1;
    }
    return 0;
}
