#ifndef _CMD_RUN_HPP
#define _CMD_RUN_HPP

#include <string>

namespace cmd
{

/**
 * @brief Run environment.
 *
 * @param kvdbPath Path to KVDB folder.
 * @param eventEndpoint Endpoint of the server.
 * @param apiEndpoint Endpoint of the API.
 * @param queueSize Size of the event ingestion queue.
 * @param threads Number of environment threads.
 * @param fileStorage Path to asset folders.
 * @param environment Name of the environment to be loaded.
 * @param logLevel Log level.
 */
void run(const std::string& kvdbPath,
         const std::string& eventEndpoint,
         const std::string& apiEndpoint,
         const int queueSize,
         const int threads,
         const std::string& fileStorage,
         const std::string& environment,
         const int logLevel);
} // namespace cmd

#endif // _CMD_RUN_HPP
