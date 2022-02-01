#ifndef _PARSER_H
#define _PARSER_H

#include <algorithm>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#include "argparse/argparse.hpp"

/**
 * @brief Defines all parser functionality.
 *
 */
namespace parser
{

/**
 * @brief Parser is a class made to parse the command line input.
 *
 */
class Parser
{

private:
    std::string m_endpoint_config;
    std::string m_storage_path;

public:
    /**
     * @brief Construct a new Parser object and extracts the arguments saving them into the class variables
     *
     * @param argc Number of arguments passed.
     * @param argv List the arguments passed via console.
     */
    Parser(int argc, char *argv[]);

    /**
     * @brief Extracts the arguments saving them into the class variables.
     *
     * @param argc Number of arguments passed.
     * @param argv List the arguments passed via console.
     */
    void parse(int argc, char *argv[]);

    /**
     * @brief Returns the endpoint configuration that has been previously parsed
     *
     * @return std::string m_endpoint_config
     */
    std::string getEndpointConfig();

    /**
     * @brief Returns the storage path that has been previously parsed
     *
     * @return std::string m_storage_path
     */
    std::string getStoragePath();

};

} // namespace parser

#endif // _PARSER_H
