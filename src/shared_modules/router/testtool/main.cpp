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
std::string MODE;
std::atomic<size_t> COUNT = 0;

static void clean()
{
    if (MODE.compare("publisher") == 0)
    {
        if (PROVIDER)
        {
            PROVIDER->stop();
            PROVIDER.reset();
        }
    }
    else if (MODE.compare("subscriber") == 0)
    {
        if (SUBSCRIPTOR)
        {
            SUBSCRIPTOR.reset();
        }
    }
    else if (MODE.compare("broker") == 0)
    {
        RouterModule::instance().stop();
    }
}

int main(int argc, const char* argv[])
{
    try
    {
        CmdLineArgs args(argc, argv);

        MODE = args.mode();
        if (MODE == "publisher")
        {
            PROVIDER = std::make_unique<RouterProvider>(args.topic(), false);
            PROVIDER->start();
        }
        else if (MODE == "subscriber")
        {
            SUBSCRIPTOR = std::make_unique<RouterSubscriber>(args.topic(), args.subscriberId(), false);

            SUBSCRIPTOR->subscribe(
                [&](const std::vector<char>& message)
                {
                    std::cout << "Received message #" << ++COUNT << ": ";
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
        else if (MODE == "broker")
        {
            RouterModule::instance().start();
        }
        else
        {
            CmdLineArgs::showHelp();
            clean();
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
        clean();
    }
    catch (const std::exception& e)
    {
        CmdLineArgs::showHelp();
        return 1;
    }
    return 0;
}
