#pragma once

#include "json.hpp"

#include <stdexcept>
#include <string>

namespace wazuh::container_instances
{

    class YamlParseError : public std::runtime_error
    {
    public:
        using std::runtime_error::runtime_error;
    };

    /// Parses one YAML document into JSON. All scalars become strings except plain
    /// (unquoted) true/false — kubeconfig consumers need nothing else. Aliases,
    /// anchors and multi-document streams are rejected. @throws YamlParseError.
    [[nodiscard]] nlohmann::json yamlToJson(const std::string& yamlText);

} // namespace wazuh::container_instances
