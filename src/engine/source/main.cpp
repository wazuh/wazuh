

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
#include "register.hpp"
#include "router.hpp"
#include "threadPool.hpp"
#include "protocolHandler.hpp"

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

    // hardcoded catalog storage driver
    // TODO: use argparse module
    catalog::Catalog _catalog;
    try
    {
        _catalog.setStorageDriver(make_unique<DiskStorage>(storagePath));
    }
    catch (const std::exception & e)
    {
        LOG(ERROR) << "Engine error, got exception while configuring catalog: " << e.what() << endl;
        return 1;
    }

    // Builder
    try
    {
        builder::internals::registerBuilders();
    }
    catch (const std::exception & e)
    {
        LOG(ERROR) << "Engine error, got exception while registering builders: " << e.what() << endl;
        return 1;
    }
    builder::Builder<catalog::Catalog> _builder(_catalog);
    engineserver::ProtocolHandler p;

    //Handle ThreadPool
    auto sc = rxcpp::schedulers::make_scheduler<threadpool::ThreadPool>(3);
    auto scheduledTask =
        server.output().flat_map([&sc, p](engineserver::endpoints::BaseEndpoint::EventObs o)
                                 { return o.observe_on(rxcpp::identity_same_worker(sc.create_worker())).map([=](string s){
                                     return p.parse(s);
                                 }); });

    // auto sc = rxcpp::schedulers::make_scheduler<threadpool::ThreadPool>(2);
    // auto scheduledTask =
    //     server.output().flat_map([&sc](engineserver::endpoints::BaseEndpoint::EventObs o)
    //                              { return o; });

    // Build router
    // TODO: Integrate filter creation with builder and default route with catalog
    router::Router<builder::Builder<catalog::Catalog>> router{scheduledTask, _builder};

    try
    {
        // Default route
        router.add(
            "test_route",
            [](auto j)
            {
                // TODO: check basic fields are present
                return true;
            },
            "test_environment");
    }
    catch (const std::exception & e)
    {
        LOG(ERROR) << "Engine error, got exception while building default route: " << e.what() << endl;
        return 1;
    }

    server.run();

    return 0;
}
