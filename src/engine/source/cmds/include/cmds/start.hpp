#ifndef _CMD_START_HPP
#define _CMD_START_HPP

#include <memory>
#include <string>

#include <CLI/CLI.hpp>

namespace cmd::start
{

/**
 * @brief Start engine.
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
struct Options
{
    std::string kvdbPath;
    std::string eventEndpoint;
    std::string apiEndpoint;
    int queueSize;
    int threads;
    std::string fileStorage;
    std::string environment;
    int logLevel;
};
void run(const Options& options);

void configure(CLI::App& app);
} // namespace cmd::start

#endif // _CMD_START_HPP
