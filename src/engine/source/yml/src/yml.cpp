#include <yml/yml.hpp>

#include <iostream>
#include <string>
#include <vector>

namespace yml
{

rapidjson::Document Converter::loadYMLfromFile(const std::string& filepath)
{
    YAML::Node root = YAML::LoadFile(filepath);
    rapidjson::Document doc;

    rapidjson::Value val = yamlToJson(root, doc.GetAllocator());
    doc.CopyFrom(val, doc.GetAllocator());

    return doc;
}

rapidjson::Value Converter::parseScalar(const YAML::Node& node, rapidjson::Document::AllocatorType& allocator)
{
    rapidjson::Value v;
    if (QUOTED_TAG == node.Tag())
    {
        v.SetString(node.as<std::string>().c_str(), allocator);
    }
    else if (int i = 0; YAML::convert<int>::decode(node, i))
    {
        v.SetInt(i);
    }
    else if (int64_t i = 0; YAML::convert<int64_t>::decode(node, i))
    {
        v.SetInt64(i);
    }
    else if (double d = 0.0f; YAML::convert<double>::decode(node, d))
    {
        v.SetDouble(d);
    }
    else if (bool b = false; YAML::convert<bool>::decode(node, b))
    {
        v.SetBool(b);
    }
    else if (std::string s; YAML::convert<std::string>::decode(node, s))
    {
        v.SetString(s.c_str(), s.size(), allocator);
    }
    else
    {
        v.SetNull();
    }

    return v;
}

YAML::Node Converter::parseScalar(const rapidjson::Value& node)
{
    YAML::Node n;
    if (node.IsString())
    {
        n = node.GetString();
    }
    else if (node.IsInt())
    {
        n = node.GetInt();
    }
    else if (node.IsDouble())
    {
        n = node.GetDouble();
    }
    else if (node.IsBool())
    {
        n = node.GetBool();
    }
    else
    {
        n = YAML::Node();
    }

    return n;
}

rapidjson::Document Converter::loadYMLfromString(const std::string& yamlStr)
{
    YAML::Node root = YAML::Load(yamlStr);
    rapidjson::Document doc;

    rapidjson::Value val = yamlToJson(root, doc.GetAllocator());
    doc.CopyFrom(val, doc.GetAllocator());

    return doc;
}

YAML::Node Converter::jsonToYaml(const rapidjson::Value& value)
{
    YAML::Node node;
    if (value.IsObject())
    {
        for (auto& m : value.GetObject())
        {
            node[m.name.GetString()] = jsonToYaml(m.value);
        }
    }
    else if (value.IsArray())
    {
        for (auto& v : value.GetArray())
        {
            node.push_back(jsonToYaml(v));
        }
    }
    else
    {
        node = parseScalar(value);
    }

    return node;
}

rapidjson::Value Converter::yamlToJson(const YAML::Node& root, rapidjson::Document::AllocatorType& allocator)
{
    rapidjson::Value v;

    switch (root.Type())
    {
        case YAML::NodeType::Null: v.SetNull(); break;

        case YAML::NodeType::Scalar: v = parseScalar(root, allocator); break;

        case YAML::NodeType::Sequence:
            v.SetArray();

            for (const auto& node : root)
            {
                v.PushBack(yamlToJson(node, allocator), allocator);
            }

            break;

        case YAML::NodeType::Map:
            v.SetObject();

            for (const auto& it : root)
            {
                v.AddMember(rapidjson::Value(it.first.as<std::string>().c_str(), allocator),
                            yamlToJson(it.second, allocator),
                            allocator);
            }

            break;

        default: v.SetNull(); break;
    }

    return v;
}

namespace utils
{
namespace
{

YAML::Node sortKeysRecursively(const YAML::Node& node)
{
    if (!node.IsMap())
    {
        return node;
    }

    YAML::Node sortedNode;
    std::vector<std::string> sortedKeys;
    for (const auto& kv : node)
    {
        sortedKeys.push_back(kv.first.as<std::string>());
    }
    std::sort(sortedKeys.begin(), sortedKeys.end());

    for (const auto& key : sortedKeys)
    {
        if (node[key].IsMap())
        {
            sortedNode[key] = sortKeysRecursively(node[key]);
        }
        else
        {
            sortedNode[key] = node[key];
        }
    }

    return sortedNode;
};
} // namespace
std::string ymlToPrettyYaml(const std::string& ymlStr, bool sort)
{

    YAML::Node node;
    try
    {
        node = YAML::Load(ymlStr);
    }
    catch (const YAML::ParserException& e)
    {
        throw std::runtime_error("Error parsing yml string: " + std::string(e.what()));
    }

    // Crear un Emitter y configurarlo para ser "pretty"
    YAML::Emitter out;
    // Pretty YML
    out.SetIndent(2);
    out.SetMapFormat(YAML::Block);
    out.SetSeqFormat(YAML::Block);

    if (sort)
    {
        // Ordenar las claves recursivamente
        YAML::Node sortedNode = sortKeysRecursively(node);
        out << sortedNode;
    }
    else
    {
        out << node;
    }

    return out.c_str();
};
} // namespace utils
} // namespace yml
