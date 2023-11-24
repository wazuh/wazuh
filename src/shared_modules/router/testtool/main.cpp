#include "cmdArgsParser.hpp"
#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/idl.h"
#include "routerModule.hpp"
#include "routerProvider.hpp"
#include "routerSubscriber.hpp"
#include <atomic>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

std::unique_ptr<RouterProvider> PROVIDER;
std::unique_ptr<RouterSubscriber> SUBSCRIPTOR;

int main(int argc, const char* argv[])
{
    CmdLineArgs args(argc, argv);

    atexit(
        []()
        {
            if (PROVIDER)
            {
                PROVIDER->stop();
                PROVIDER.reset();
            }
            if (SUBSCRIPTOR)
            {
                SUBSCRIPTOR.reset();
            }
            RouterModule::instance().stop();
        });

    if (args.mode() == "publisher")
    {
        PROVIDER = std::make_unique<RouterProvider>(args.topic());
        PROVIDER->start();
    }
    else if (args.mode() == "subscriber")
    {
        SUBSCRIPTOR = std::make_unique<RouterSubscriber>(args.topic(), args.subscriberId(), false);
        std::atomic<size_t> count = 0;

        SUBSCRIPTOR->subscribe(
            [&](const std::vector<char>& message)
            {
                std::cout << "Received message #" << ++count << ": ";
                auto fbsPath = args.fbsPath();

                if (fbsPath.empty())
                {
                    std::cout << std::string(message.begin(), message.end()) << std::endl;
                }
                else
                {
                    flatbuffers::IDLOptions options;
                    options.strict_json = true;
                    flatbuffers::Parser parser(options);
                    std::string schemaStr;

                    if (!flatbuffers::LoadFile(fbsPath.c_str(), false, &schemaStr))
                    {
                        throw std::runtime_error("Unable to load schema file.");
                    }
                    if (!parser.Parse(schemaStr.c_str()))
                    {
                        throw std::runtime_error("Unable to parse schema file.");
                    }

                    std::string strData;
                    flatbuffers::GenText(parser, reinterpret_cast<const uint8_t*>(message.data()), &strData);
                    std::cout << strData << std::endl;
                }
            });
    }
    else if (args.mode() == "broker")
    {
        RouterModule::instance().start();
    }
    else
    {
        CmdLineArgs::showHelp();
        return 1;
    }

    std::cout << "Press 'q' to exit." << std::endl;
    std::string data;
    while (std::getline(std::cin, data))
    {
        const auto message = std::vector<char>(data.begin(), data.end());

        if (message.empty())
        {
            continue;
        }

        if (message[0] == 'q')
        {
            break;
        }

        if (PROVIDER)
        {
            std::cout << "Sending message: " << data << std::endl;
            PROVIDER->send(message);
        }
    }
    return 0;
}
