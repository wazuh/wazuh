

// TODO: rename files as wazuh style
// TODO: delete dummy test/benchmarks examples, no longer needed
// TODO: QoL CMakeLists
#include "glog/logging.h"
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "Catalog.hpp"
#include "builder.hpp"
#include "catalog/storageDriver/disk/DiskStorage.hpp"
#include "cliParser.hpp"
#include "engineServer.hpp"
#include "graph.hpp"
#include "json.hpp"
#include "protocolHandler.hpp"
#include "register.hpp"
#include "router.hpp"
#include "threadPool.hpp"

using namespace std;

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

std::atomic<int> total = 0;
rxcpp::composite_subscription lifetime;

int main(int argc, char * argv[])
{

    google::InitGoogleLogging(argv[0]);
    vector<string> serverArgs;
    string storagePath;
    try
    {
        cliparser::CliParser cliInput(argc, argv);
        serverArgs.push_back(cliInput.getEndpointConfig());
        storagePath = cliInput.getStoragePath();
    }
    catch (const std::exception & e)
    {
        LOG(ERROR) << "Error while parsing arguments: " << e.what() << endl;
        return 1;
    }

    static rxcpp::schedulers::run_loop rl;
    rxcpp::observe_on_one_worker mainthread = rxcpp::observe_on_run_loop(rl);

    engineserver::EngineServer server;
    try
    {
        server.configure(serverArgs, mainthread);
    }
    catch (const exception & e)
    {
        // TODO: implement log with GLOG
        LOG(ERROR) << "Engine error, got exception while configuring server: " << e.what() << endl;
        // TODO: handle if errors on close can happen
        // server.close();
        return 1;
    }

    engineserver::ProtocolHandler p;
    auto serverObs = server.output();

    // rxcpp::observable<std::string> safeServerObs = serverObs.on_error_resume_next(
    //     [&](auto eptr)
    //     {
    //         LOG(ERROR) << "safeServerObs treated error: " << rxcpp::util::what(eptr) << std::endl;
    //         return safeServerObs;
    //     });

    // auto safeServerObs = serverObs.retry(
    //     [=](auto eptr)
    //     {
    //         LOG(ERROR) << "safeServerObs treated error: " << rxcpp::util::what(eptr) << std::endl;
    //     });

    serverObs.subscribe(
        [](json::Document event)
        {
            total++;
            //LOG(INFO) << "[" << std::this_thread::get_id() << "]" << total << std::endl;
        },
        [](std::exception_ptr eptr) { LOG(ERROR) << "Subscriber got error: " << rxcpp::util::what(eptr) << endl; },
        []() { LOG(INFO) << "[" << this_thread::get_id() << "] Subscriber completed" << std::endl; });


    // rxcpp::observable<int> uvwLoop = rxcpp::observable<>::create<int>(
    //     [&](auto s)
    //     {

    //         s.on_completed();
    //     });

    // uvwLoop.subscribe_on(mainthread)
    //     .subscribe([](int v) {}, [](auto eptr) {}, []() { LOG(ERROR) << "UVW Loop completed" << std::endl; });

    signal(SIGINT,
           [](auto s)
           {
               LOG(INFO) << "[" << this_thread::get_id() << "] Total proccessed: " << total << std::endl;
               lifetime.unsubscribe();
           });

    while (lifetime.is_subscribed())
    {
        server.run();
        while (!rl.empty() && rl.peek().when < rl.now())
        {
            rl.dispatch();
        }

        // Throttle down
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    return 0;
}
