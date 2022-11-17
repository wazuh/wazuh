#ifndef _CMD_KVDB_HPP
#define _CMD_KVDB_HPP

//TODO: delete after kvdbApi is fully working

#include <string>

namespace cmd
{

enum class InputType
{
    JSON
};

/**
 * @brief Get the Input Type object from string
 *
 * @param inputType Input type as string
 * @return InputType
 */
InputType stringToInputType(const std::string& inputType);

/**
 * @brief Generate KVDB database from input file
 *
 * @param kvdbPath Path to store KVDB database
 * @param kvdbName Name of the created KVDB database
 * @param inputFile Path to input file
 * @param inputType Type of input file
 */
void kvdb(const std::string& kvdbPath,
          const std::string& kvdbName,
          const std::string& inputFile,
          InputType inputType);
} // namespace cmd

#endif // _CMD_KVDB_HPP
