

// TODO: rename files as wazuh style
// TODO: delete dummy test/benchmarks examples, no longer needed
// TODO: QoL CMakeLists
#include "glog/logging.h"
#include <stdexcept>
#include <string>
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

    engineserver::EngineServer server;
    try
    {
        server.configure(serverArgs);
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

    std::atomic<int> total = 0;
    serverObs.map([=](std::string event) { return p.parse(event); })
        .subscribe(
            [&](json::Document event)
            {
                total++;
                LOG(INFO) << total << std::endl;
            },
            [](std::exception_ptr eptr) { LOG(ERROR) << "Subscriber got error: " << rxcpp::util::what(eptr) << endl; },
            []() { LOG(INFO) << "Subscriber completed" << std::endl; });

    server.run();

    return 0;
}
