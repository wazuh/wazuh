#include "cmdArgsParser.hpp"
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
                std::cout << std::string(message.data(), message.size()) << std::endl;
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
