#ifndef _CMD_TEST_HPP
#define _CMD_TEST_HPP

#include <string>
#include <vector>

#include <CLI/CLI.hpp>

namespace cmd::test
{

/**
 * @brief Run environment in test mode. Inputs from stdin, outputs event to stdout and
 * debug to stderr.
 *
 * @param kvdbPath Path to KVDB folder.
 * @param fileStorage Path to asset folders.
 * @param environment Name of the environment to be loaded.
 * @param logLevel Log level.
 * @param debugLevel Debug level.
 * @param assetTrace Trace specific assets.
 * @param protocolQueue Queue of the protocol.
 * @param protocolLocation Location of the protocol.
 */
struct Options
{
    std::string kvdbPath;
    std::string fileStorage;
    std::string environment;
    int logLevel;
    int debugLevel;
    std::vector<std::string> assetTrace;
    char protocolQueue;
    std::string protocolLocation;
};
void run(const Options& options);

void configure(CLI::App& app);
} // namespace cmd::test

#endif // _CMD_TEST_HPP
