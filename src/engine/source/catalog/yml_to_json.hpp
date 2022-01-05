#ifndef __YML_TO_JSON_H__
#define __YML_TO_JSON_H__

#include <iostream>
#include "yaml-cpp/yaml.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

// #TODO Adds a thread-safe mechanism (?)
// #TODO Adds test
// #TODO Convert to static class
namespace yml2json
{

    namespace internal
    {

        inline rapidjson::Value parse_scalar(const YAML::Node& node, rapidjson::Document::AllocatorType& allocator)
        {

            rapidjson::Value v;
            int i;
            double d;
            bool b;
            std::string s;

            if (YAML::convert<int>::decode(node, i))
            {
                v.SetInt(i);
            }
            else if (YAML::convert<double>::decode(node, d))
            {
                v.SetDouble(d);
            }
            else if (YAML::convert<bool>::decode(node, b))
            {
                v.SetBool(b);
            }
            else if (YAML::convert<std::string>::decode(node, s))
            {
                v.SetString(s.c_str(), s.size(), allocator);
            }
            else
            {
                v.SetNull();
            }

            return v;
        }


        inline rapidjson::Value yaml2json(const YAML::Node& root, rapidjson::Document::AllocatorType& allocator)
        {

            rapidjson::Value v;

            switch (root.Type())
            {
                case YAML::NodeType::Null:
                    v.SetNull();
                    break;

                case YAML::NodeType::Scalar:
                    v = parse_scalar(root, allocator);
                    break;

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
                        v.AddMember(rapidjson::Value(it.first.as<std::string>().c_str(), allocator), yaml2json(it.second, allocator), allocator);
                    }

                    break;

                default:
                    v.SetNull();
                    break;
            }


            return v;

        }

    }

    inline rapidjson::Document loadYMLfromFile(const std::string& filepath)
    {
        // YAML::Node root = YAML::LoadAllFromFile(filepath)[x];
        YAML::Node root = YAML::LoadFile(filepath);
        rapidjson::Document doc, tmpAllocator;
        rapidjson::Document::AllocatorType& allocator = tmpAllocator.GetAllocator();

        rapidjson::Value val = internal::yaml2json(root, allocator);
        doc.CopyFrom(val, doc.GetAllocator());

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

}

#endif // __YML_TO_JSON_H__
