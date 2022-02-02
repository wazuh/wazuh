

// TODO: rename files as wazuh style
// TODO: delete dummy test/benchmarks examples, no longer needed
// TODO: QoL CMakeLists
#include <stdexcept>
#include <string>
#include <vector>

#include "Catalog.hpp"
#include "builder.hpp"
#include "catalog/storageDriver/disk/DiskStorage.hpp"
#include "engineServer.hpp"
#include "graph.hpp"
#include "json.hpp"
#include "router.hpp"
#include "cliParser.hpp"

using namespace std;

int main(int argc, char * argv[])
{
    // Build server first
    // TODO: use argumentparser module
    cliparser::CliParser cliInput(argc, argv);
    vector<string> serverArgs{cliInput.getEndpointConfig()};
    string test = "test string";
    engineserver::EngineServer server;
    try
    {
        server.configure(serverArgs);
    }
    catch (const exception & e)
    {
        // TODO: implement log with GLOG
        cerr << "Engine error, got exception while configuring server: " << e.what() << endl;
        // TODO: handle if errors on close can happen
        // server.close();
        return 1;
    }

    // hardcoded catalog storage driver
    // TODO: use argparse module
    string storagePath = cliInput.getStoragePath();
    catalog::Catalog _catalog;
    try
    {
        _catalog.setStorageDriver(make_unique<DiskStorage>(storagePath));
    }
    catch (const std::exception & e)
    {
        cerr << "Engine error, got exception while configuring catalog: " << e.what() << endl;
        return 1;
    }

    // Builder
    const catalog::Catalog * catalogPtr = &_catalog;
    builder::Builder<catalog::Catalog> _builder(catalogPtr);

    // Build router
    // TODO: Integrate filter creation with builder and default route with catalog
    router::Router<builder::Builder<catalog::Catalog>> router{server.output(), _builder};

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
        cerr << "Engine error, got exception while building default route: " << e.what() << endl;
        return 1;
    }

    // main loop is the server run
    // TODO: implemented multiple endpoints listening, only implemented tcp
    server.run();

    return 0;
}
