#include <iostream>
#include <string>
#include <algorithm>
#include <chrono>
#include <thread>

#include "json.hpp"

#include "rapidjson/document.h"
#include "rapidjson/pointer.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include "rxcpp/rx.hpp"


using namespace std;

namespace builder::shared
{

    void Json::set(std::string path, const rapidjson::Value & v) 
    {
        std::replace(std::begin(path), std::end(path), '.', '/');
        auto ptr = rapidjson::Pointer(path.c_str());
        if (ptr.IsValid())
        {
            ptr.Set(this->doc, v);
        }
        else
        {
            throw std::invalid_argument("Invalid json path for this json");
        }
    }

    rapidjson::Value * Json::get(std::string path) 
    {
        std::replace(std::begin(path), std::end(path), '.', '/');
        auto ptr = rapidjson::Pointer(path.c_str());
        if (ptr.IsValid())
        {
            return ptr.Get(this->doc);
        }
        throw std::invalid_argument("Invalid json path for this json");
    }

    bool Json::check(std::string path, const rapidjson::Value & expected) 
    {
        std::replace(std::begin(path), std::end(path), '.', '/');
        auto ptr = rapidjson::Pointer(path.c_str());
        if (ptr.IsValid()) 
        {
            auto got = ptr.Get(this->doc);
            if (got)
            {
                return *got == expected;
            }
        }
        return false;
    }

    bool Json::check(std::string path) 
    {
        std::replace(std::begin(path), std::end(path), '.', '/');
        auto ptr = rapidjson::Pointer(path.c_str());
        return ptr.IsValid();
    }

    std::string Json::str() {
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType,
                          rapidjson::ASCII<>> writer(buffer);
        this->doc.Accept(writer);
        return buffer.GetString();
    }
}
