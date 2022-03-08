#ifndef _JSON_H
#define _JSON_H

#include <algorithm>
#include <chrono>
#include <iostream>
#include <string>

#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/pointer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "rxcpp/rx.hpp"

namespace json
{
using Value = rapidjson::Value;

/**
 * @brief Document is a json class based on rapidjson library.
 *
 */
class Document
{
private:
public:
    rapidjson::Document m_doc;

    Document(){};
    explicit Document(const char * json)
    {
        rapidjson::ParseResult ok = m_doc.Parse(json);
        if (!ok)
        {
            std::string err = rapidjson::GetParseError_En(ok.Code());
            throw std::invalid_argument("Unable to build json document because: " + err + " at " +
                                        std::to_string(ok.Offset()));
        }
    };
    Document(const Document & e)
    {
        this->m_doc.CopyFrom(e.m_doc, this->m_doc.GetAllocator());
    };
    Document(const rapidjson::Value & v)
    {
        this->m_doc.CopyFrom(v, this->m_doc.GetAllocator());
    };

    /**
     * @brief Prepare a path to be used in json::setPP
     *
     * Preapend a / to the path if it is not already present and remplace all '.' by '/'
     * @param path path to be prepared
     * @return std::string path prepared
     */
    static std::string preparePath(std::string path)
    {
        if (path.front() != '/')
        {
            path.insert(0, "/");
        }
        // TODO: Remplace '/' by '\/'
        // TODO: escape '.' when is preceded by a '\'
        // TODO: Not sure if this is the best way to do this
        std::replace(std::begin(path), std::end(path), '.', '/');
        return path;
    }

    /**
     * @brief Method to set a value in a given json path.
     *
     * @param path json path of the value that will be set.
     * Prepared with json::preparePath before calling this method
     * @param v new value that will be set.
     */
    void set(std::string path, const rapidjson::Value & v)
    {
        //std::replace(std::begin(path), std::end(path), '.', '/');
        auto ptr = rapidjson::Pointer(path.c_str());
        if (ptr.IsValid())
        {
            ptr.Set(this->m_doc, v);
        }
        else
        {
            throw std::invalid_argument("Invalid json path for this json");
        }
    }

    /**
     * @brief Set a value `v` in the json document.
     *
     * The path is obtain with the key of the value.
     * Not prepared with json::preparePath before calling this method
     * @param v value that will be set.
     */
    void set(const Document & v)
    {
        // TODO Call or not call json::preparePath?
        std::string path = preparePath(v.m_doc.MemberBegin()->name.GetString());

        auto ptr = rapidjson::Pointer(path.c_str());
        if (ptr.IsValid())
        {
            ptr.Set(this->m_doc, v.m_doc.MemberBegin()->value);
        }
        else
        {
            throw std::invalid_argument("Invalid json path for this json");
        }
    }

    /**
     * @brief -----
     * @param v 
     */
    void setReference(const Document & v)
    {
        // TODO: Write a test and doc for this method and check if it works
        // TODO Call or not call json::preparePath?
        std::string pathTarget = preparePath(v.m_doc.MemberBegin()->name.GetString());
        auto ptrTarget = rapidjson::Pointer(pathTarget.c_str());

        if (!v.m_doc.MemberBegin()->value.IsString()) {
            throw std::runtime_error("Reference must be a string");
        }
        std::string pathRef = preparePath(v.m_doc.MemberBegin()->value.GetString());
        auto ptrRef = rapidjson::Pointer(pathRef.c_str());

        if (ptrTarget.IsValid() && ptrRef.IsValid())
        {
            ptrTarget.Set(this->m_doc, *ptrRef.Get(this->m_doc));
        }
        else
        {
            throw std::runtime_error("Invalid json path for this json");
        }
    }

    /**
     * @brief Method that returns a pointer to the value of a given json path.
     *
     * @param path json path of the value that will be returned.
     * Prepared with json::preparePath before calling this method
     * @return rapidjson::Value * Pointer to the value of path. // TODO why Can be nullptr
     * @throws std::invalid_argument if the path is invalid (not found).
     */
    const rapidjson::Value * get(std::string path) const
    {
        auto ptr {rapidjson::Pointer(path.c_str())};
        if (ptr.IsValid())
        {
            return ptr.Get(this->m_doc);
        }
        throw std::invalid_argument("Invalid json path for this json");
    }

    /**
     * @brief Method to check if the value stored on the given path is equal to
     * the value given as argument.
     *
     * @param path json path of the value that will be compared.
     * @param expected Expected value of the path.
     *
     * @return boolean True if the value pointed by path is equal to expected.
     * False if its not equal.
     */
    bool check(std::string path, const rapidjson::Value * expected) const
    {
        auto ptr {rapidjson::Pointer(preparePath(path).c_str())};
        if (ptr.IsValid())
        {
            auto got = ptr.Get(this->m_doc);
            if (got)
            {
                return *got == *expected;
            }
        }
        return false;
    }

    bool check(const Document & expected) const
    {
        auto ptr = rapidjson::Pointer(preparePath(expected.begin()->name.GetString()).c_str());
        if (ptr.IsValid())
        {
            auto got = ptr.Get(this->m_doc);
            auto gotExpected = ptr.Get(expected.m_doc);
            if (got and gotExpected)
            {
                return *got == *gotExpected;
            }
        }
        return false;
    }

    bool contains(const std::string & field) const
    {
        // TODO DOC THIS
        //auto ptr = rapidjson::Pointer(preparePath(field).c_str());
        auto ptr = rapidjson::Pointer(field.c_str());
        if (ptr.IsValid())
        {
            auto got = ptr.Get(this->m_doc);
            if (got)
            {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Method to check if the value stored on the given path exists.
     *
     * @param path json path of the value that will be checked.
     *
     * @return boolean True if the value pointed by path exists. False if it does
     * not.
     */
    bool exists(const std::string& path) const
    {

        auto ptr = rapidjson::Pointer(preparePath(path).c_str());
        if (ptr.IsValid() && ptr.Get(this->m_doc))
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    /**
     * @brief Method to write a Json object into a string.
     *
     * @return string Containing the info of the Json object.
     */
    std::string str() const
    {
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(
            buffer);
        this->m_doc.Accept(writer);
        return buffer.GetString();
    }

    auto begin() const -> decltype(this->m_doc.MemberBegin())
    {
        return this->m_doc.MemberBegin();
    }
    auto end() const -> decltype(this->m_doc.MemberEnd())
    {
        return this->m_doc.MemberEnd();
    }
    auto getObject()
    {
        return this->m_doc.GetObject();
    }
    auto & getAllocator()
    {
        return this->m_doc.GetAllocator();
    }

    Document operator=(const Document & other)
    {
        if (this == &other)
        {
            return *this;
        }

        this->m_doc.CopyFrom(other.m_doc, this->m_doc.GetAllocator());

        return *this;
    }
};

}; // namespace json

#endif // _JSON_H
