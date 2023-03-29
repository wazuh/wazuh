#ifndef _H_TESTS_COMMON
#define _H_TESTS_COMMON

#include <logging/logging.hpp>

constexpr char DEFAULT_TESTS_LOG_PATH[] {"/tmp/engine_code_tests.log"};

/**
 * @brief Initializes the logging module for tests
 *
 */
void inline initLogging(void)
{
    // Logging setup
    logging::LoggingConfig logConfig;
    logConfig.logLevel = "off";
    logConfig.filePath = DEFAULT_TESTS_LOG_PATH;
    logging::loggingInit(logConfig);
}

#endif // _H_TESTS_COMMON
