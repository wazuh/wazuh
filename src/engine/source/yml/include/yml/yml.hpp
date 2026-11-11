// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _YML_H
#define _YML_H

#include <iostream>

#include <yaml-cpp/yaml.h>

#include <base/json.hpp>

namespace yml
{
constexpr auto QUOTED_TAG = "!";

/**
 * @brief Class for converting between YAML and JSON formats using RapidJSON and YAML-CPP libraries.
 */
class Converter
{
public:
    /**
     * @brief Load a YAML file and return a RapidJSON document.
     *
     * @param filepath Filepath of the YAML file.
     *
     * @return json::Document RapidJSON document loaded from the YAML file.
     */
    static json::Document loadYMLfromFile(const std::string& filepath);

    /**
     * @brief Load a YAML string and return a RapidJSON document.
     *
     * @param yamlStr YAML string.
     *
     * @return json::Document RapidJSON document loaded from the YAML string.
     */
    static json::Document loadYMLfromString(const std::string& yamlStr);

    /**
     * @brief Convert a YAML node to a RapidJSON value.
     *
     * @param root YAML node to convert.
     * @param allocator RapidJSON document allocator instance.
     *
     * @return json::Value Converted RapidJSON value.
     */
    static json::Value yamlToJson(const YAML::Node& root, json::Document::AllocatorType& allocator);

    /**
     * @brief Convert a RapidJSON scalar node to a YAML node.
     *
     * @param node RapidJSON scalar node to convert.
     *
     * @return YAML::Node Converted YAML node.
     */
    static YAML::Node parseScalar(const json::Value& node);

    /**
     * @brief Convert a YAML node to a RapidJSON value.
     *
     * @param node YAML node to convert.
     * @param allocator RapidJSON document allocator instance.
     *
     * @return json::Value Converted RapidJSON value.
     * TODO: Delete this, should not use rapidjson
     */
    static json::Value parseScalar(const YAML::Node& node, json::Document::AllocatorType& allocator);

    /**
     * @brief Convert a RapidJSON value to a YAML node.
     *
     * @param value RapidJSON value to convert.
     *
     * @return YAML::Node Converted YAML node.
     * TODO: Delete this, should not use rapidjson
     */
    static YAML::Node jsonToYaml(const json::Value& value);
};

namespace utils
{

/**
 * @brief Convert a YML string to a pretty YAML string.
 *
 * @param ymlStr YML string to convert.
 * @param sort Sort the YAML keys alphabetically.
 * @return std::string Converted YAML string.
 * @throw std::runtime_error if the YML string is invalid.
 */
std::string ymlToPrettyYaml(const std::string& ymlStr, bool sort = false);

} // namespace utils

} // namespace yml

#endif // _YML_H
