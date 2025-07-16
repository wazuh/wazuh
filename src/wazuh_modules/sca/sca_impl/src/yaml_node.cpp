#include "yaml_node.hpp"
#include "yaml_document.hpp"

#include <iostream>

YamlNode::YamlNode(yaml_document_t* doc, yaml_node_t* nodePtr)
    : m_document(doc)
    , m_node(nodePtr)
{
    if (!m_node)
    {
        return;
    }

    switch (m_node->type)
    {
        case YAML_SCALAR_NODE: m_type = Type::Scalar; break;
        case YAML_SEQUENCE_NODE: m_type = Type::Sequence; break;
        case YAML_MAPPING_NODE: m_type = Type::Mapping; break;
        case YAML_NO_NODE: m_type = Type::Undefined; break;
        default: m_type = Type::Undefined; break;
    }
}

void YamlNode::DumpYamlStructure(unsigned int indent) const
{
    std::string padding(indent, ' ');
    std::cout << padding << "Node Type: " << GetNodeTypeAsString();
    if (IsScalar())
    {
        std::cout << ", Value: " << AsString();
    }
    std::cout << std::endl;

    if (IsMap())
    {
        for (const auto& [key, val] : AsMap())
        {
            std::cout << padding << "- Key: " << key << std::endl;
            val.DumpYamlStructure(indent + 2);
        }
    }
    else if (IsSequence())
    {
        auto seq = AsSequence();
        for (size_t i = 0; i < seq.size(); ++i)
        {
            std::cout << padding << "- Index [" << i << "]" << std::endl;
            seq[i].DumpYamlStructure(indent + 2);
        }
    }
}

YamlNode::Type YamlNode::GetNodeType() const
{
    return m_type;
}

std::string YamlNode::GetNodeTypeAsString() const
{
    switch (m_type)
    {
        case Type::Scalar: return "Scalar";
        case Type::Sequence: return "Sequence";
        case Type::Mapping: return "Mapping";
        case Type::Undefined: // fallthrough
        default: return "Undefined";
    }
}

bool YamlNode::IsScalar() const
{
    return m_type == Type::Scalar;
}

bool YamlNode::IsSequence() const
{
    return m_type == Type::Sequence;
}

bool YamlNode::IsMap() const
{
    return m_type == Type::Mapping;
}

std::string YamlNode::AsString() const
{
    if (!IsScalar())
    {
        throw std::runtime_error("Node is not a scalar");
    }
    return std::string(reinterpret_cast<const char*>(m_node->data.scalar.value));
}

std::vector<YamlNode> YamlNode::AsSequence() const
{
    if (!IsSequence())
    {
        throw std::runtime_error("Node is not a sequence");
    }
    if (!sequence_cache.empty())
    {
        return sequence_cache;
    }

    for (yaml_node_item_t* item = m_node->data.sequence.items.start; item < m_node->data.sequence.items.top; ++item)
    {
        sequence_cache.emplace_back(m_document, yaml_document_get_node(m_document, *item));
    }
    return sequence_cache;
}

std::map<std::string, YamlNode> YamlNode::AsMap() const
{
    if (!IsMap())
    {
        throw std::runtime_error("Node is not a map");
    }
    if (!map_cache.empty())
    {
        return map_cache;
    }

    for (yaml_node_pair_t* pair = m_node->data.mapping.pairs.start; pair < m_node->data.mapping.pairs.top; ++pair)
    {
        auto key_node = yaml_document_get_node(m_document, pair->key);
        auto val_node = yaml_document_get_node(m_document, pair->value);
        if (key_node && key_node->type == YAML_SCALAR_NODE)
        {
            std::string key = reinterpret_cast<const char*>(key_node->data.scalar.value);
            map_cache[key] = YamlNode(m_document, val_node);
        }
    }
    return map_cache;
}

const YamlNode& YamlNode::operator[](const std::string& key) const
{
    if (!IsMap())
    {
        throw std::runtime_error("Not a map node");
    }
    const auto map = AsMap();
    if (map.find(key) == map.end())
    {
        throw std::out_of_range("Key not found");
    }
    return map_cache[key];
}

const YamlNode& YamlNode::operator[](size_t index) const
{
    if (!IsSequence())
    {
        throw std::runtime_error("Not a sequence node");
    }
    const auto seq = AsSequence();
    if (index >= seq.size())
    {
        throw std::out_of_range("Index out of bounds");
    }
    return sequence_cache[index];
}

YamlNode& YamlNode::operator[](const std::string& key)
{
    if (!IsMap())
    {
        throw std::runtime_error("Not a map node");
    }
    const auto map = AsMap();
    if (map.find(key) == map.end())
    {
        throw std::out_of_range("Key not found");
    }
    return map_cache[key];
}

YamlNode& YamlNode::operator[](size_t index)
{
    if (!IsSequence())
    {
        throw std::runtime_error("Not a sequence node");
    }
    const auto seq = AsSequence();
    if (index >= seq.size())
    {
        throw std::out_of_range("Index out of bounds");
    }
    return sequence_cache[index];
}

void YamlNode::SetScalarValue(const std::string& new_value)
{
    if (!IsScalar())
    {
        throw std::runtime_error("Not a scalar node");
    }

    // Free the old string
    free(m_node->data.scalar.value);

    // This new string will be owned and freed by the document on destruction
    const auto newValue = strdup(new_value.c_str());

    m_node->data.scalar.value = reinterpret_cast<yaml_char_t*>(newValue);
    m_node->data.scalar.length = new_value.size();
}

bool YamlNode::HasKey(const std::string& key) const
{
    if (IsMap())
    {
        const auto& map = AsMap();
        return map.find(key) != map.end();
    }
    else if (IsSequence())
    {
        const auto seq = AsSequence();
        for (const auto& item : seq)
        {
            if (item.IsMap())
            {
                const auto& itemMap = item.AsMap();
                if (itemMap.find(key) != itemMap.end())
                {
                    return true;
                }
            }
        }
        return false;
    }
    return false;
}

void YamlNode::RemoveKey(const std::string& key)
{
    if (!IsMap())
    {
        throw std::runtime_error("Not a map node");
    }
    yaml_node_t* const map_node = m_node;

    yaml_node_pair_t* out = map_node->data.mapping.pairs.start;
    for (yaml_node_pair_t* in = map_node->data.mapping.pairs.start; in < map_node->data.mapping.pairs.top; ++in)
    {
        const auto key_node = yaml_document_get_node(m_document, in->key);
        std::string current_key = reinterpret_cast<const char*>(key_node->data.scalar.value);
        if (current_key != key)
        {
            *out++ = *in;
        }
    }
    map_node->data.mapping.pairs.top = out;
    map_cache.clear();
}

int YamlNode::GetId() const
{
    for (int i = 1; i <= m_document->nodes.top - m_document->nodes.start; ++i)
    {
        const yaml_node_t* const candidate = yaml_document_get_node(m_document, i);
        if (candidate == m_node)
        {
            return i;
        }
    }
    throw std::runtime_error("Node not found in document");
};

YamlNode YamlNode::CreateEmptySequence(const std::string& key)
{
    // if (!IsMap())
    // {
    //     throw std::runtime_error("Not a map node");
    // }

    // yaml_char_t* const key_str = reinterpret_cast<yaml_char_t*>(strdup(key.c_str()));
    // const yaml_char_t* tag = reinterpret_cast<const yaml_char_t*>(YAML_STR_TAG);
    // const int key_id =
    //     yaml_document_add_scalar(m_document, tag, key_str, static_cast<int>(key.length()), YAML_PLAIN_SCALAR_STYLE);

    // // Free the key string - yaml_document_add_scalar will make its own copy
    // free(key_str);

    // const int seq_id = yaml_document_add_sequence(m_document, tag, YAML_BLOCK_SEQUENCE_STYLE);

    // const int mapping_id = GetId();

    // yaml_document_append_mapping_pair(m_document, mapping_id, key_id, seq_id);

    // // important to clear our cache here
    // map_cache.clear();

    // yaml_node_t* const sequence_node = yaml_document_get_node(m_document, seq_id);
    // return YamlNode(m_document, sequence_node);
    return {};
}

void YamlNode::AppendToSequence(const std::string& value)
{
    // if (!IsSequence())
    // {
    //     throw std::runtime_error("Not a sequence node");
    // }

    // yaml_char_t* const val_str = reinterpret_cast<yaml_char_t*>(strdup(value.c_str()));
    // const int scalar_id = yaml_document_add_scalar(m_document,
    //                                                reinterpret_cast<const yaml_char_t*>(YAML_STR_TAG),
    //                                                val_str,
    //                                                static_cast<int>(value.length()),
    //                                                YAML_PLAIN_SCALAR_STYLE);

    // free(val_str);

    // yaml_document_append_sequence_item(m_document, GetId(), scalar_id);
    // sequence_cache.clear();
}

YamlNode YamlNode::CloneInto(yaml_document_t* dest_doc) const
{
    // switch (GetNodeType())
    // {
    //     case Type::Scalar:
    //     {
    //         const std::string value = AsString();
    //         yaml_char_t* const val_str = reinterpret_cast<yaml_char_t*>(strdup(value.c_str()));
    //         const int scalar_id = yaml_document_add_scalar(dest_doc,
    //                                                        reinterpret_cast<const yaml_char_t*>(YAML_STR_TAG),
    //                                                        val_str,
    //                                                        static_cast<int>(value.length()),
    //                                                        YAML_PLAIN_SCALAR_STYLE);
    //         free(val_str);
    //         return YamlNode(dest_doc, yaml_document_get_node(dest_doc, scalar_id));
    //     }
    //     case Type::Sequence:
    //     {
    //         const int seq_id = yaml_document_add_sequence(
    //             dest_doc, reinterpret_cast<const yaml_char_t*>(YAML_SEQ_TAG), YAML_BLOCK_SEQUENCE_STYLE);
    //         for (const auto& item : AsSequence())
    //         {
    //             const YamlNode cloned = item.CloneInto(dest_doc);
    //             yaml_document_append_sequence_item(dest_doc, seq_id, cloned.GetId());
    //         }
    //         return YamlNode(dest_doc, yaml_document_get_node(dest_doc, seq_id));
    //     }
    //     case Type::Mapping:
    //     {
    //         const int map_id = yaml_document_add_mapping(
    //             dest_doc, reinterpret_cast<const yaml_char_t*>(YAML_MAP_TAG), YAML_BLOCK_MAPPING_STYLE);
    //         for (const auto& [key, val] : AsMap())
    //         {
    //             yaml_char_t* const key_str = reinterpret_cast<yaml_char_t*>(strdup(key.c_str()));
    //             const int key_id = yaml_document_add_scalar(dest_doc,
    //                                                         reinterpret_cast<const yaml_char_t*>(YAML_STR_TAG),
    //                                                         key_str,
    //                                                         static_cast<int>(key.length()),
    //                                                         YAML_PLAIN_SCALAR_STYLE);
    //             free(key_str);
    //             const YamlNode cloned_val = val.CloneInto(dest_doc);
    //             yaml_document_append_mapping_pair(dest_doc, map_id, key_id, cloned_val.GetId());
    //         }
    //         return YamlNode(dest_doc, yaml_document_get_node(dest_doc, map_id));
    //     }
    //     case Type::Undefined: // fallthrough
    //     default: throw std::runtime_error("Unsupported or undefined node type");
    // }
}

YamlDocument YamlNode::Clone() const
{
    YamlDocument new_doc;
    yaml_document_initialize(&new_doc.m_document, nullptr, nullptr, nullptr, 0, 0);
    yaml_parser_initialize(&new_doc.m_parser);
    new_doc.m_loaded = true;
    CloneInto(&new_doc.m_document);
    return new_doc;
}
