#ifndef _UTILS_YML_H
#define _UTILS_YML_H

#include <iostream>

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <yaml-cpp/yaml.h>

// #TODO Adds a thread-safe mechanism (?)
namespace utilsYml
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
     * @return rapidjson::Document RapidJSON document loaded from the YAML file.
     */
    static rapidjson::Document loadYMLfromFile(const std::string& filepath);

    /**
     * @brief Load a YAML string and return a RapidJSON document.
     *
     * @param yamlStr YAML string.
     * @return rapidjson::Document RapidJSON document loaded from the YAML string.
     */
    static rapidjson::Document loadYMLfromString(const std::string& yamlStr);

    /**
     * @brief Convert a YAML node to a RapidJSON value.
     *
     * @param root YAML node to convert.
     * @param allocator RapidJSON document allocator instance.
     * @return rapidjson::Value Converted RapidJSON value.
     */
    static rapidjson::Value yaml2json(const YAML::Node& root, rapidjson::Document::AllocatorType& allocator);

    /**
     * @brief Convert a RapidJSON scalar node to a YAML node.
     *
     * @param node RapidJSON scalar node to convert.
     * @param allocator RapidJSON document allocator instance.
     * @return YAML::Node Converted YAML node.
     */
    static YAML::Node parse_scalar(const rapidjson::Value& node);

    /**
     * @brief Convert a YAML node to a RapidJSON value.
     *
     * @param node YAML node to convert.
     * @param allocator RapidJSON document allocator instance.
     * @return rapidjson::Value Converted RapidJSON value.
     */
    static rapidjson::Value parse_scalar(const YAML::Node& node, rapidjson::Document::AllocatorType& allocator);

    /**
     * @brief Convert a RapidJSON value to a YAML node.
     *
     * @param value RapidJSON value to convert.
     * @return YAML::Node Converted YAML node.
     */
    static YAML::Node json2yaml(const rapidjson::Value& value);
};
} // namespace yml

#endif // _UTILS_YML_H
