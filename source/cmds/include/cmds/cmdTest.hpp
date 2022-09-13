#ifndef _CMD_TEST_HPP
#define _CMD_TEST_HPP

#include <string>
#include <vector>

namespace cmd
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
 * @param traceAll Trace all assets.
 * @param assetTrace Trace specific assets.
 * @param protocolQueue Queue of the protocol.
 * @param protocolLocation Location of the protocol.
 */
void test(const std::string& kvdbPath,
          const std::string& fileStorage,
          const std::string& environment,
          int logLevel,
          int debugLevel,
          bool traceAll,
          const std::vector<std::string>& assetTrace,
          char protocolQueue,
          const std::string& protocolLocation);
} // namespace cmd

#endif // _CMD_TEST_HPP
