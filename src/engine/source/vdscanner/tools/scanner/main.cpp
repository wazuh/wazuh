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

#include <exception>

#include <httplib.h>

#include "base/logging.hpp"
#include "vdscanner/scanOrchestrator.hpp"

#include "argsParser.hpp"

int main(const int argc, const char* argv[])
{
    try
    {
        CmdLineArgs args(argc, argv);
        logging::start({args.getLogFilePath(), logging::Level::Debug});

        vdscanner::ScanOrchestrator scanOrchestrator;
        httplib::Server svr;

        svr.Post("/vulnerability/scan",
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
            [functionName = logging::getLambdaName(__FUNCTION__, "setLogger")](const auto& req, const auto& res)
            {
                LOG_DEBUG_L(functionName.c_str(),
                            "Method: {} - Request: {} - Response status: {}",
                            req.method,
                            req.body,
                            res.status);
            });

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
