#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <wiconnector/windexerconnector.hpp>

#include <base/logging.hpp>

TEST(WIC, DummyTest)
{
    logging::testInit(logging::Level::Debug);
    auto logFunction = logging::createStandaloneLogFunction();
    wiconnector::Config config;
    config.hosts = {"http://localhost:9200"};
    config.username = "admin";
    config.password = "admin";
    wiconnector::WIndexerConnector connector(config, logFunction);

    connector.index("test-index", R"({"field": "value"})");
    // sleep 1 second to allow async indexing to complete
    std::this_thread::sleep_for(std::chrono::seconds(1));
    GTEST_SKIP() << "No tests implemented yet";
}
