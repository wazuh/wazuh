#ifndef _YML_TO_JSON_H
#define _YML_TO_JSON_H

#include <iostream>

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <yaml-cpp/yaml.h>

// #TODO Adds a thread-safe mechanism (?)
// #TODO Adds test
// #TODO Convert to static class
namespace yml2json
{

namespace internal
{
constexpr auto QUOTED_TAG = "!";

rapidjson::Value parse_scalar(const YAML::Node& node,
                                     rapidjson::Document::AllocatorType& allocator)
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

YAML::Node parse_scalar(const rapidjson::Value& node)
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

YAML::Node json2yaml(const rapidjson::Value& value)
{
    YAML::Node node;
    if (value.IsObject())
    {
        for (auto& m : value.GetObject())
        {
            node[m.name.GetString()] = json2yaml(m.value);
        }
    }
    else if (value.IsArray())
    {
        for (auto& v : value.GetArray())
        {
            node.push_back(json2yaml(v));
        }
    }
    else
    {
        node = parse_scalar(value);
    }

    return node;
}

rapidjson::Value yaml2json(const YAML::Node& root,
                                  rapidjson::Document::AllocatorType& allocator)
{

    rapidjson::Value v;

    switch (root.Type())
    {
        case YAML::NodeType::Null: v.SetNull(); break;

        case YAML::NodeType::Scalar: v = parse_scalar(root, allocator); break;

        case YAML::NodeType::Sequence:
            v.SetArray();

            for (auto&& node : root)
            {
                v.PushBack(yaml2json(node, allocator), allocator);
            }

            break;

        case YAML::NodeType::Map:
            v.SetObject();

            for (auto&& it : root)
            {
                v.AddMember(
                    rapidjson::Value(it.first.as<std::string>().c_str(), allocator),
                    yaml2json(it.second, allocator),
                    allocator);
            }

            break;

        default: v.SetNull(); break;
    }

    return v;
}

} // namespace internal

inline rapidjson::Document loadYMLfromFile(const std::string& filepath)
{
    // YAML::Node root = YAML::LoadAllFromFile(filepath)[x];
    YAML::Node root = YAML::LoadFile(filepath);
    rapidjson::Document doc; //, tmpAllocator;
    // rapidjson::Document::AllocatorType& allocator =
    // tmpAllocator.GetAllocator();

    rapidjson::Value val = internal::yaml2json(root, doc.GetAllocator());
    // doc.CopyFrom(val, doc.GetAllocator());

    return doc;
}

/** Loads a YAML string and returns a rapidjson::Document.
 *
 * @param yamlStr The YAML string to load.
 * @return rapidjson::Document The parsed YAML string.
 * @throws YAML::ParserException If the YAML string is invalid.
 */
inline rapidjson::Document loadYMLfromString(const std::string& yamlStr)
{
    YAML::Node root = YAML::Load(yamlStr);
    rapidjson::Document doc, tmpAllocator;
    rapidjson::Document::AllocatorType& allocator = tmpAllocator.GetAllocator();

    rapidjson::Value val = internal::yaml2json(root, allocator);
    doc.CopyFrom(val, doc.GetAllocator());

    return doc;
}

} // namespace yml2json

#endif // _YML_TO_JSON_H
