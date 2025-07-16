
#pragma once

#include <yaml.h>

#include <map>
#include <string>
#include <vector>

class YamlDocument;

/// @brief Class representing a YAML node
class YamlNode
{
public:
    /// @brief Type of a YAML node
    enum class Type
    {
        Scalar,
        Sequence,
        Mapping,
        Undefined
    };

    /// @brief Constructor for a YAML node
    /// @param doc Pointer to the yaml_document_t object parenting this node
    /// @param node Pointer to the yaml_node_t this object represents
    YamlNode(yaml_document_t* doc, yaml_node_t* node);

    /// @brief Default constructor
    YamlNode() = default;

    /// @brief Gets the type of the YAML node
    /// @return Type of the node
    Type GetNodeType() const;

    /// @brief Gets the type of the YAML node as a string
    /// @return String representation of the node type
    std::string GetNodeTypeAsString() const;

    /// @brief Checks if the YAML node is a scalar
    /// @return True if the node is a scalar, false otherwise
    bool IsScalar() const;

    /// @brief Checks if the YAML node is a sequence
    /// @return True if the node is a sequence, false otherwise
    bool IsSequence() const;

    /// @brief Checks if the YAML node is a map
    /// @return True if the node is a map, false otherwise
    bool IsMap() const;

    /// @brief Gets the ID (or index) of the YAML node
    /// @details For nodes loaded from a file, there is no way to get the ID other than
    /// traversing the YAML document comparing the nodes and returning the corresponding index.
    /// @return ID of the node
    int GetId() const;

    /// @brief Gets the value of the YAML node as a string
    /// @return String value of the node
    std::string AsString() const;

    /// @brief Gets the value of the YAML node as a sequence
    /// @return Vector of YamlNode objects representing the sequence
    std::vector<YamlNode> AsSequence() const;

    /// @brief Gets the value of the YAML node as a map
    /// @return Map of YamlNode objects representing the map
    std::map<std::string, YamlNode> AsMap() const;

    /// @brief Gets the value of the YAML node (mapping only)
    /// @param key Key of the map to get
    /// @return YamlNode object representing the value
    const YamlNode& operator[](const std::string& key) const;

    /// @brief Gets the value of the YAML node (sequence only)
    /// @param index Index of the sequence to get
    /// @return YamlNode object representing the value
    const YamlNode& operator[](size_t index) const;

    /// @brief Gets the value of the YAML node (mapping only)
    /// @param key Key of the map to get
    /// @return YamlNode object representing the value
    YamlNode& operator[](const std::string& key);

    /// @brief Gets the value of the YAML node (sequence only)
    /// @param index Index of the sequence to get
    /// @return YamlNode object representing the value
    YamlNode& operator[](size_t index);

    /// @brief Sets the value of the YAML node
    /// @param new_value New value to set
    void SetScalarValue(const std::string& new_value);

    /// @brief Checks if the YAML node has a key
    /// @param key Key to check
    /// @return True if the key exists, false otherwise
    bool HasKey(const std::string& key) const;

    /// @brief Removes a key from the YAML node
    /// @param key Key to remove
    void RemoveKey(const std::string& key);

    /// @brief Creates an empty sequence in the YAML node
    /// @param key Key to create the sequence under
    /// @return YamlNode object representing the sequence
    YamlNode CreateEmptySequence(const std::string& key);

    /// @brief Appends a value to the YAML node sequence
    /// @param value Value to append
    void AppendToSequence(const std::string& value);

    /// @brief Dump the YAML structure to the console for debugging purposes
    /// @param indent Indentation level
    void DumpYamlStructure(unsigned int indent = 2) const;

    /// @brief Clones the YAML node
    /// @return YamlDocument object holding the cloned node
    YamlDocument Clone() const;

private:
    /// @brief Clones the YAML node into a new document
    /// @param dest_doc Document to clone the node into
    /// @return YamlNode object representing the cloned node
    YamlNode CloneInto(yaml_document_t* dest_doc) const;

    /// @brief The underlying yaml_document_t
    yaml_document_t* m_document = nullptr;

    /// @brief The underlying yaml_node_t
    yaml_node_t* m_node = nullptr;

    /// @brief The type of the YAML node
    Type m_type = Type::Undefined;

    /// @brief Cache for mapping nodes
    mutable std::map<std::string, YamlNode> map_cache;

    /// @brief Cache for sequence nodes
    mutable std::vector<YamlNode> sequence_cache;

    /// @brief Cache for scalar nodes
    mutable std::string scalar_cache;
};
