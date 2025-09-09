#include <gtest/gtest.h>
#include <gmock/gmock.h>


#include <indexerConnector/wIndexerConnector.hpp>

TEST(WIC, DummyTest)
{
    auto connector = wiconnector::WIndexerConnector("localhost", 9200);
    GTEST_SKIP() << "No tests implemented yet";
}
