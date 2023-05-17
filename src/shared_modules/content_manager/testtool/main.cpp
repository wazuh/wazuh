#include "contentManager.hpp"
#include "contentRegister.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <iostream>
#include <thread>
#include <vector>

int main()
{
    auto& instance = ContentModule::instance();

    // Server
    instance.start(nullptr);

    // CLiente -> vulnenability  detector
    ContentRegister registerer {"test", {{"interval", 10}, {"ondemand", true}}};
    std::this_thread::sleep_for(std::chrono::seconds(5));
    std::cout << "changing interval" << std::endl;
    registerer.changeSchedulerInterval(10);
    // End client

    std::this_thread::sleep_for(std::chrono::seconds(60));

    // Stop server
    instance.stop();

    return 0;
}
