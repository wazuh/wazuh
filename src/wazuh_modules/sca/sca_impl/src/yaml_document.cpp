
#include "yaml_document.hpp"
#include "yaml_node.hpp"

#include <fstream>

#include <iostream>

YamlDocument::YamlDocument()
    : m_loaded(false) {};

YamlDocument::YamlDocument(const std::filesystem::path& filename)
{
    std::ifstream file(filename.c_str());
    if (!file)
    {
        throw std::runtime_error("Cannot open file");
    };

    if (!Load(file))
    {
        // TODO: Log("Failed to parse YAML document:" filename.string().c_str());
    }
}

YamlDocument::YamlDocument(const std::string& yaml_content)
{
    std::istringstream ss(yaml_content);

    if (!Load(ss))
    {
        // TODO: Log("Failed to parse YAML content");
    }
}

YamlDocument::~YamlDocument()
{
    if (m_loaded)
    {
        yaml_document_delete(&m_document);
    }
    yaml_parser_delete(&m_parser);
}

bool YamlDocument::IsValidDocument() const
{
    return m_loaded;
}

bool YamlDocument::Load(std::istream& input)
{
    yaml_parser_initialize(&m_parser);
    std::string content((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    yaml_parser_set_input_string(&m_parser, reinterpret_cast<const unsigned char*>(content.c_str()), content.size());
    m_loaded = yaml_parser_load(&m_parser, &m_document);

    return m_loaded;
}

YamlNode YamlDocument::GetRoot()
{
    auto root = yaml_document_get_root_node(&m_document);
    if (!root)
    {
        throw std::runtime_error("Empty YAML document");
    }
    return YamlNode(&m_document, root);
}
