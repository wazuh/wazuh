#include <gtest/gtest.h>

#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>

#include "metrics.hpp"

int main(int argc, char** argv)
{
    Metrics::instance().initMetrics("metrics_unit_tests", "/root/repos/wazuh/src/engine/build/source/metrics/input_files/metrics-config.json");
    logging::LoggingConfig logConfig;
    logConfig.logLevel = logging::LogLevel::Off;
    logging::loggingInit(logConfig);

    ::testing::InitGoogleTest(&argc, argv);
    auto result = RUN_ALL_TESTS();
    Metrics::instance().clean();
    return result;
}
