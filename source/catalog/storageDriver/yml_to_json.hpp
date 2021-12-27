#ifndef __YML_TO_JSON_H__
#define __YML_TO_JSON_H__

#include <iostream>
#include "yaml-cpp/yaml.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

namespace yml2json
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


    inline std::string loadyaml(const std::string& filepath)
    {
        // YAML::Node root = YAML::LoadAllFromFile(filepath)[x];
        YAML::Node root = YAML::LoadFile(filepath);


        rapidjson::Document doc;
        rapidjson::Document::AllocatorType& allocator = doc.GetAllocator();
        doc.SetArray();

        rapidjson::Value val = yaml2json(root, allocator);
        doc.PushBack(val, allocator);


        //doc.AddMember("root", val, allocator);
        // output
        rapidjson::StringBuffer SB;
        rapidjson::Writer<rapidjson::StringBuffer> writer(SB);
        doc.Accept(writer);

        std::cout << SB.GetString() << std::endl;


        return "123";
    }

}

#endif // __YML_TO_JSON_H__
