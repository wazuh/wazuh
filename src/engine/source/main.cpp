

// TODO: rename files as wazuh style
// TODO: delete dummy test/benchmarks examples, no longer needed
// TODO: QoL CMakeLists
#include <stdexcept>
#include <string>
#include <vector>

#include "Catalog.hpp"
#include "builder.hpp"
#include "engineServer.hpp"
#include "graph.hpp"
#include "json.hpp"
#include "router.hpp"

using namespace std;

int main(int argc, char * argv[])
{
    // Build server first
    // Fake server args
    // TODO: use argumentparser module
    vector<string> serverArgs{"tcp:localhost:5054"};

    engineserver::EngineServer server;
    try
    {
        server.configure(serverArgs);
    }
    catch (const exception & e)
    {
        // TODO: implement log with GLOG
        cerr << "Engine error, got exception while building server: " << e.what() << endl;
        // TODO: handle if errors on close can happen
        // server.close();
        return 1;
    }

    // TODO
    // Get Catalog, needed to be injected on Builder
    // Refactor catalog, storage drivers should not be exposed outside catalog
    // Add default constructor to safe handle exceptions on initialization
    // catalog::Catalog catalog{};

    // Get Builder, needed to be injected on Router
    // TODO: Add default constructor to safe handle exceptions on initialization
    // builder::Builder<catalog::Catalog> builder{catalog};

    // Build router
    // TODO: implement default constructor to handle exceptions and safe abort
    // TODO: change handleRouter so instead of a function it receives an observable from server output
    auto handlerRouter = [](rxcpp::subscriber<json::Document> s) {};
    auto builderRouter = [](string s) { return rxcpp::subjects::subject<json::Document>{}; };
    Router::Router<json::Document> router{handlerRouter, builderRouter};

    // TODO: get router configuration (should have one by default?)
    // TODO: safe handle exceptions
    // router.add(defaultRoute);

    // At this points all submodules are built and linked (Router building links)
    // Start server

    // Currently launches detached thread
    server.run();

    return 0;
}
