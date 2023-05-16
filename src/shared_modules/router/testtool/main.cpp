#include "routerModule.hpp"
#include "routerProvider.hpp"
#include "routerSubscriber.hpp"
#include <atomic>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

int main()
{
    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest");
    auto provider = std::make_unique<RouterProvider>("test");
    RouterModule::instance().initialize([](const modules_log_level_t level, const std::string& log)
                                        { std::cout << "Log: " << log << std::endl; });
    std::cout << "Initialized" << std::endl;
    // Router::instance().providerInit("test");
    provider->start();
    // RouterProvider::instance().initLocal("test");
    std::cout << "Provider initialized" << std::endl;

    std::atomic<size_t> count = 0;
    // RouterSubscriber::instance().addLocal("test", [&](std::shared_ptr<std::vector<char>> data) { ++count; });
    /*RouterSubscriber::instance().addLocal("test",
                                                 [&](std::shared_ptr<std::vector<char>> data)
                                                 {
                                                     ++count;
                                                     std::cout << "Data: " << data->data() << std::endl;
                                                 });*/

    subscriptor->subscribe(
        [&](const std::vector<char>& message)
        {
            ++count;
            std::cout << "Data: " << message.data() << std::endl;
        });
    std::cout << "Subscriber initialized" << std::endl;

    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::string data {"Hello world"};
    auto message = std::vector<char>(data.begin(), data.end());

    for (int i = 0; i < 50; ++i)
    {
        provider->send(message);
    }

    std::this_thread::sleep_for(std::chrono::seconds(5));

    std::cout << "Destroying " << count << std::endl;
    RouterModule::instance().destroy();
    return 0;
}
