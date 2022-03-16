#ifndef _JSON_H
#define _JSON_H

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/pointer.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

namespace json
{

using Value = rapidjson::Value;

/**
 * @brief Document is a json class based on rapidjson library.
 *
 */
class Document
{
public:
    rapidjson::Document m_doc;

public:
    /**
     * @brief Construct a new Document object
     *
     */
    Document() = default;

    /**
     * @brief Construct a new Document object from json string
     *
     * @param json
     */
    explicit Document(const char * json)
    {
        rapidjson::ParseResult result = m_doc.Parse(json);
        if (!result)
        {
            throw std::invalid_argument("Unable to build json document because: " +
                                        static_cast<std::string>(rapidjson::GetParseError_En(result.Code())) + " at " +
                                        std::to_string(result.Offset()));
        }
    }

    // TODO: may be unnecesary or movable only
    /**
     * @brief Construct a new Document object from a value
     *
     * @param v
     */
    Document(const rapidjson::Value & v)
    {
        this->m_doc.CopyFrom(v, this->m_doc.GetAllocator());
    }

    /**
     * @brief Construct a new Document object
     *
     * @param other
     */
    Document(const Document & other)
    {
        this->m_doc.CopyFrom(other.m_doc, this->m_doc.GetAllocator());
    }

    /**
     * @brief Construct a new Document object
     *
     * @param other
     */
    Document(Document && other) noexcept : m_doc{std::move(other.m_doc)}
    {
    }

    /**
     * @brief Asignation
     *
     * @param other
     * @return Document&
     */
    Document & operator=(const Document & other)
    {
        this->m_doc.CopyFrom(other.m_doc, this->m_doc.GetAllocator());
        return *this;
    }

    /**
     * @brief Move asignation
     *
     * @param other
     * @return Document&
     */
    Document & operator=(Document && other) noexcept
    {
        this->m_doc = std::move(other.m_doc);
        return *this;
    }

    /**
     * @brief Get value of path, throws if not found, use exists before
     *
     * @param path
     * @return const rapidjson::Value&
     */
    const rapidjson::Value & get(const std::string & path) const
    {
        auto ptr = rapidjson::Pointer(path.c_str());
        if (ptr.IsValid())
        {
            auto tmpPtr = ptr.Get(this->m_doc);
            if (tmpPtr)
            {
                return *tmpPtr;
            }
            else
            {
                throw std::invalid_argument("Error, field not found: " + path);
            }
        }
        else
        {
            throw std::invalid_argument("Error, received invalid path in get function: " + path);
        }
    }

    /**
     * @brief Method to set a value in a given json path.
     *
     * @param path json path of the value that will be set.
     * @param v new value that will be set.
     */
    void set(const std::string & path, const rapidjson::Value & v)
    {
        auto ptr = rapidjson::Pointer(path.c_str());
        if (ptr.IsValid())
        {
            ptr.Set(m_doc, v);
        }
        else
        {
            throw std::invalid_argument("Error, received invalid path in set function: " + path);
        }
    }

    /**
     * @brief Set the `to` field with `from` value
     *
     * @param to
     * @param from
     */
    void set(const std::string & to, const std::string & from)
    {
        auto toPtr = rapidjson::Pointer(to.c_str());
        auto fromPtr = rapidjson::Pointer(from.c_str());

        if (toPtr.IsValid() && fromPtr.IsValid())
        {
            auto fromValue = fromPtr.Get(this->m_doc);
            if (fromValue)
            {
                // Static cast is used to ensure new allocation is made
                toPtr.Set(this->m_doc, static_cast<const rapidjson::Value &>(*fromValue));
            }
            // TODO: Handle failed case;
        }
        else
        {
            throw std::invalid_argument("Error, received invalid path in set function: " + to + " -> " + from);
        }
    }

    /**
     * @brief Compare if `source` field's value equals `reference` field's value
     *
     * @param source
     * @param reference
     *
     * @return True if equals, false othrewise
     */
    bool equals(const std::string & source, const std::string & reference) const
    {
        auto sourcePtr = rapidjson::Pointer(source.c_str());
        auto referencePtr = rapidjson::Pointer(reference.c_str());

        if (sourcePtr.IsValid() && referencePtr.IsValid())
        {
            auto sValue = sourcePtr.Get(this->m_doc);
            auto rValue = referencePtr.Get(this->m_doc);
            if (sValue && rValue)
            {
                return *sValue == *rValue;
            }
            else
            {
                return false;
            }
        }
        else
        {
            throw std::invalid_argument("Error, received invalid path in equals function: " + source +
                                        " == " + reference);
        }
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
    bool equals(const std::string & path, const rapidjson::Value & expected) const
    {
        auto ptr = rapidjson::Pointer(path.c_str());
        if (ptr.IsValid())
        {
            const auto got = ptr.Get(this->m_doc);
            if (got)
            {
                return *got == expected;
            }
            else
            {
                return false;
            }
        }
        else
        {
            throw std::invalid_argument("Error, received invalid path in equals function: " + path);
        }
    }

    /**
     * @brief Check if field denoted by path is present in the document
     *
     * @param path
     * @return true
     * @return false
     */
    bool exists(const std::string & path) const
    {
        auto ptr = rapidjson::Pointer(path.c_str());
        if (ptr.IsValid())
        {
            if (ptr.Get(this->m_doc))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            throw std::invalid_argument("Error, received invalid path in contains function: " + path);
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
        m_doc.Accept(writer);
        return buffer.GetString();
    }

    /**
     * @brief Method to write a Json object into a prettyfied string.
     *
     * @return string Containing the info of the Json object.
     */
    std::string prettyStr() const
    {
        rapidjson::StringBuffer buffer;
        rapidjson::PrettyWriter<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(
            buffer);
        this->m_doc.Accept(writer);
        return buffer.GetString();
    }

    // TODO: this functions may be unnecessary
    auto begin() const -> decltype(this->m_doc.MemberBegin())
    {
        return m_doc.MemberBegin();
    }
    auto end() const -> decltype(m_doc.MemberEnd())
    {
        return m_doc.MemberEnd();
    }

    auto getObject() const -> decltype(this->m_doc.GetObject())
    {
        return m_doc.GetObject();
    }

    auto getAllocator() -> decltype(this->m_doc.GetAllocator())
    {
        return m_doc.GetAllocator();
    }
};

/**
 * @brief Adds root slash if not present and replaces dots with slashes
 *
 * @param path
 * @return std::string
 */
static std::string formatJsonPath(const std::string & path)
{
    std::string formatedPath{path};
    if (formatedPath.front() != '/')
    {
        formatedPath.insert(0, "/");
    }
    // TODO: Remplace '/' by '\/'
    // TODO: escape '.' when is preceded by a '\'
    // TODO: Not sure if this is the best way to do this
    std::replace(std::begin(formatedPath), std::end(formatedPath), '.', '/');

    return formatedPath;
}

} // namespace json

#endif // _JSON_H
