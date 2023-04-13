#ifndef _H_TESTS_COMMON
#define _H_TESTS_COMMON

#include <logging/logging.hpp>

/**
 * @brief Initializes the logging module for tests
 *
 */
void inline initLogging(void)
{
    static bool initialized = false;

    if (!initialized)
    {
        // Logging setup
        logging::LoggingConfig logConfig;
        logConfig.logLevel = "off";
        logConfig.filePath = "";
        logging::loggingInit(logConfig);
        initialized = true;
    }
}

#endif // _H_TESTS_COMMON
