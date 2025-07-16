#pragma once

#include "yaml_node.hpp"

/// @brief Interface for YAML document class
class IYamlDocument
{
public:
    /// @brief Destructor
    virtual ~IYamlDocument() = default;

    /// @brief Gets the root node of the YAML document
    /// @return YamlNode object representing the root node
    virtual YamlNode GetRoot() = 0;

    /// @brief Checks if the YAML document has been loaded with no errors
    /// @return True if the document has been successfully loaded, false otherwise
    virtual bool IsValidDocument() const = 0;
};
