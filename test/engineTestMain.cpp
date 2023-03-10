#include <gtest/gtest.h>

#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>

int main(int argc, char** argv)
{
    logging::LoggingConfig logConfig;
    logConfig.logLevel = spdlog::level::off;
    logging::loggingInit(logConfig);

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
