#pragma once

#include <iyaml_document.hpp>
#include <yaml.h>

#include <filesystem>
#include <string>

/// @brief Class representing a YAML document
class YamlDocument : public IYamlDocument
{
public:
    /// @brief Constructor for loading a YAML document from a file
    YamlDocument(const std::filesystem::path& filename);

    /// @brief Constructor for loading a YAML document from a string
    YamlDocument(const std::string& yaml_content);

    /// @brief Default constructor
    YamlDocument();

    /// @brief Destructor
    ~YamlDocument();

    /// @copydoc IYamlDocument::GetRoot
    YamlNode GetRoot() override;

    /// @copydoc IYamlDocument::IsValidDocument
    bool IsValidDocument() const override;

    friend class YamlNode;

private:
    /// @brief yaml_parser_t object used to parse the YAML document
    yaml_parser_t m_parser;

    /// @brief Flag indicating whether the document has been loaded
    bool m_loaded;

    /// @brief yaml_document_t object representing the parsed YAML document
    yaml_document_t m_document;

    /// @brief Loads the YAML document from the given input stream
    /// @param input The input stream to load the document from
    /// @return True if the document was successfully loaded, false otherwise
    bool Load(std::istream& input);
};
