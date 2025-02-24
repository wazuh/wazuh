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
#include "flatbuffers/idl.h"
#include "flatbuffers/include/rsync_schema.h"
#include "flatbuffers/include/syscheck_deltas_schema.h"
#include "flatbuffers/include/syscollector_deltas_schema.h"
#include "inventoryHarvester.hpp"
#include "json.hpp"
#include "routerModule.hpp"
#include "routerProvider.hpp"
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>

std::mutex G_MUTEX;
auto constexpr MAX_LEN {65536};

enum class InputType : std::uint8_t
{
    DeltaSyscollector,
    DeltaSyscheck,
    Rsync,
    Json,
    Invalid
};

int main(const int argc, const char* argv[])
{
    try
    {
        auto& routerModule = RouterModule::instance();
        const auto& inventoryHarvester = InventoryHarvester::instance();
        CmdLineArgs cmdLineArgs(argc, argv);

        // Read json configuration file
        auto configuration = nlohmann::json::parse(std::ifstream(cmdLineArgs.getConfigurationFilePath()));

        // // If the template file path is provided, set in the configuration adding the template path.
        // // Otherwise, the default template will be used.
        if (!cmdLineArgs.getTemplateFilePath().empty())
        {
            configuration["indexer"]["template_path"] = cmdLineArgs.getTemplateFilePath();
        }

        routerModule.start();

        auto routerProviderDeltasSyscollector = RouterProvider("deltas-syscollector", true);
        auto routerProviderDeltasSyscheck = RouterProvider("deltas-syscheck", true);
        auto routerProviderRSync = RouterProvider("rsync", true);
        auto routerProviderDbUpdate = RouterProvider("wdb-agent-events", true);
        routerProviderDeltasSyscollector.start();
        routerProviderDeltasSyscheck.start();
        routerProviderRSync.start();
        routerProviderDbUpdate.start();

        // Open file to write log.
        std::ofstream logFile;
        if (!cmdLineArgs.getLogFilePath().empty())
        {
            logFile.open(cmdLineArgs.getLogFilePath());
            if (!logFile.is_open())
            {
                throw std::runtime_error("Failed to open log file: " + cmdLineArgs.getLogFilePath());
            }
        }

        const auto logFunction = [&logFile](const int logLevel,
                                            const std::string& tag,
                                            std::string_view file,
                                            const int line,
                                            const std::string& func,
                                            const std::string& message,
                                            va_list args)
        {
            auto pos = file.find_last_of('/');
            if (pos != std::string::npos)
            {
                pos++;
            }
            std::string_view fileName = file.substr(pos, file.size() - pos);
            char formattedStr[MAX_LEN] = {0};
            vsnprintf(formattedStr, MAX_LEN, message.c_str(), args);

            std::lock_guard lock(G_MUTEX);
            if (logLevel != LOG_ERROR)
            {
                std::cout << tag << ":" << fileName << ":" << line << " " << func << " : " << formattedStr << "\n";
            }
            else
            {
                std::cerr << tag << ":" << fileName << ":" << line << " " << func << " : " << formattedStr << "\n";
            }

            if (logFile.is_open())
            {
                logFile << tag << ":" << fileName << ":" << line << " " << func << " : " << formattedStr << "\n";
            }
            // Flush the log file every time a message is written.
            logFile.flush();
        };

        inventoryHarvester.start(logFunction, configuration);

        // Wait for the complete initialization and connection negotiation.
        std::this_thread::sleep_for(std::chrono::seconds(1));

        for (const auto& inputFile : cmdLineArgs.getInputFiles())
        {
            std::cout << "Processing file: " << inputFile << "\n";
            // Parse inputFile JSON.
            if (const auto jsonInputFile = nlohmann::json::parse(std::ifstream(inputFile)).dump();
                jsonInputFile.find("action") != std::string::npos)
            {
                std::vector<char> json_vector(jsonInputFile.begin(), jsonInputFile.end());
                routerProviderDbUpdate.send(json_vector);
                continue;
            }
            else
            {
                flatbuffers::Parser parser;
                parser.opts.skip_unexpected_fields_in_json = true;

                InputType inputType = InputType::Invalid;

                // If the file start with deltas_... it is a delta file.
                if (std::filesystem::path(inputFile).filename().string().find("deltas_") != std::string::npos)
                {
                    if (parser.Parse(syscollector_deltas_SCHEMA) && (parser.Parse(jsonInputFile.c_str())))
                    {
                        std::cout << "Processing syscollector deltas\n";
                        inputType = InputType::DeltaSyscollector;
                    }
                    else if (parser.Parse(syscheck_deltas_SCHEMA) && (parser.Parse(jsonInputFile.c_str())))
                    {
                        std::cout << "Processing syscheck deltas\n";
                        inputType = InputType::DeltaSyscheck;
                    }
                    else
                    {
                        std::cout << std::endl;
                        throw std::runtime_error("Error parser flatbuffers(deltas): " + parser.error_);
                    }
                }
                else if (std::filesystem::path(inputFile).filename().string().find("rsync_") != std::string::npos)
                {
                    if (parser.Parse(rsync_SCHEMA) && (parser.Parse(jsonInputFile.c_str())))
                    {
                        std::cout << "Processing rsync\n";
                        inputType = InputType::Rsync;
                    }
                    else
                    {
                        std::cout << std::endl;
                        throw std::runtime_error("Error parser flatbuffers(rsync): " + parser.error_);
                    }
                }
                else
                {
                    std::cout << "Processing json file\n";
                    inputType = InputType::Json;
                }

                if (inputType == InputType::DeltaSyscollector)
                {
                    std::vector<char> buffer {parser.builder_.GetBufferPointer(),
                                              parser.builder_.GetBufferPointer() + parser.builder_.GetSize()};
                    routerProviderDeltasSyscollector.send(buffer);
                }
                else if (inputType == InputType::DeltaSyscheck)
                {
                    std::vector<char> buffer {parser.builder_.GetBufferPointer(),
                                              parser.builder_.GetBufferPointer() + parser.builder_.GetSize()};
                    routerProviderDeltasSyscheck.send(buffer);
                }
                else if (inputType == InputType::Rsync)
                {
                    std::vector<char> buffer {parser.builder_.GetBufferPointer(),
                                              parser.builder_.GetBufferPointer() + parser.builder_.GetSize()};
                    routerProviderRSync.send(buffer);
                }
                else
                {
                    const auto jsonData = nlohmann::json::parse(jsonInputFile);
                    std::vector<char> buffer {jsonData.dump().begin(), jsonData.dump().end()};
                    routerProviderDbUpdate.send(buffer);
                }
            }
            // Wait for the complete initialization and connection negotiation.
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        std::cout << "Waiting before exit...\n";
        std::this_thread::sleep_for(std::chrono::seconds(5));

        routerProviderDeltasSyscollector.stop();
        routerProviderDeltasSyscheck.stop();
        routerProviderRSync.stop();
        routerProviderDbUpdate.stop();
        inventoryHarvester.stop();
        routerModule.stop();
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << "\n";
        CmdLineArgs::showHelp();
        return 1;
    }
    return 0;
}
