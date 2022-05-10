#ifndef _JSON_H
#define _JSON_H

#include <algorithm>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <fmt/format.h>
#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/pointer.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

class Json
{
    rapidjson::Document m_document;

private:
    Json(const rapidjson::Value& value)
    {
        m_document.CopyFrom(value, m_document.GetAllocator());
    }

    Json(const rapidjson::GenericObject<true, rapidjson::Value>& object)
    {
        m_document.SetObject();
        for (auto& [key, value] : object)
        {
            m_document.GetObject().AddMember({key, m_document.GetAllocator()},
                                             {value, m_document.GetAllocator()},
                                             m_document.GetAllocator());
        }
    }

public:
    // Constructors
    Json() = default;
    Json(const Json& other)
    {
        m_document.CopyFrom(other.m_document, m_document.GetAllocator());
    }
    explicit Json(const char* json)
    {
        rapidjson::ParseResult result = m_document.Parse(json);
        if (!result)
        {
            throw std::runtime_error(
                fmt::format("Unable to build json document because: {} at {}",
                            rapidjson::GetParseError_En(result.Code()),
                            result.Offset()));
        }
    }

    // Static Helpers
    static std::string formatJsonPath(std::string_view field)
    {
        std::string fieldPath {field};
        if (fieldPath.front() != '/')
        {
            fieldPath.insert(0, "/");
        }

        std::replace(std::begin(fieldPath), std::end(fieldPath), '.', '/');

        return fieldPath;
    }

    // Runtime functionality
    Json(Json&& other) noexcept
        : m_document {std::move(other.m_document)}
    {
    }

    Json& operator=(Json&& other) noexcept
    {
        m_document = std::move(other.m_document);
        return *this;
    }

    bool exists(std::string_view fieldPath) const
    {
        auto fieldPtr = rapidjson::Pointer(fieldPath.data());
        if (fieldPtr.IsValid())
        {
            return fieldPtr.Get(m_document) != nullptr;
        }
        else
        {
            throw std::runtime_error(
                fmt::format("Invalid json path: [{}]", fieldPath));
        }
    }

    bool equals(std::string_view fieldPath, const Json& value) const
    {
        auto fieldPtr = rapidjson::Pointer(fieldPath.data());
        if (fieldPtr.IsValid())
        {
            const auto got = fieldPtr.Get(m_document);
            return (got && *got == value.m_document);
        }
        else
        {
            throw std::runtime_error(
                fmt::format("Invalid json path: [{}]", fieldPath));
        }
    }

    bool equals(std::string_view fieldPath,
                std::string_view referencePath) const
    {
        auto fieldPtr = rapidjson::Pointer(fieldPath.data());
        auto referencePtr = rapidjson::Pointer(referencePath.data());

        if (fieldPtr.IsValid() && referencePtr.IsValid())
        {
            const auto got = fieldPtr.Get(m_document);
            const auto reference = referencePtr.Get(m_document);
            return (got && reference && *got == *reference);
        }
        else
        {
            throw std::runtime_error(fmt::format(
                "Invalid json path: [{}] or [{}]", fieldPath, referencePath));
        }
    }

    void set(std::string_view fieldPath, const Json& value)
    {
        auto fieldPtr = rapidjson::Pointer(fieldPath.data());
        if (fieldPtr.IsValid())
        {
            fieldPtr.Set(m_document, value.m_document);
        }
        else
        {
            throw std::runtime_error(
                fmt::format("Invalid json path: [{}]", fieldPath));
        }
    }

    void set(std::string_view fieldPath, std::string_view referencePath)
    {
        auto fieldPtr = rapidjson::Pointer(fieldPath.data());
        auto referencePtr = rapidjson::Pointer(referencePath.data());

        if (fieldPtr.IsValid() && referencePtr.IsValid())
        {
            const auto * reference = referencePtr.Get(m_document);
            if (reference)
            {
                fieldPtr.Set(m_document, *reference);
            }
        }
        else
        {
            throw std::runtime_error(fmt::format(
                "Invalid json path: [{}] or [{}]", fieldPath, referencePath));
        }
    }

    std::string prettyStr() const
    {
        rapidjson::StringBuffer buffer;
        rapidjson::PrettyWriter<rapidjson::StringBuffer,
                                rapidjson::Document::EncodingType,
                                rapidjson::ASCII<>>
            writer(buffer);
        this->m_document.Accept(writer);
        return buffer.GetString();
    }

    friend std::ostream& operator<<(std::ostream& os, const Json& json)
    {
        os << json.prettyStr();
        return os;
    }

    // Buildtime functionality
    size_t size() const
    {
        if (m_document.IsObject())
        {
            return m_document.GetObject().MemberCount();
        }
        else if (m_document.IsArray())
        {
            return m_document.GetArray().Size();
        }
        else
        {
            throw std::runtime_error(fmt::format(
                "Error, calling Size for non collection json type [{}]",
                typeName()));
        }
    }

    bool isNull() const
    {
        return m_document.IsNull();
    }

    bool isBool() const
    {
        return m_document.IsBool();
    }

    bool isInt() const
    {
        return m_document.IsInt();
    }

    bool isUint() const
    {
        return m_document.IsUint();
    }

    bool isInt64() const
    {
        return m_document.IsInt64();
    }

    bool isUint64() const
    {
        return m_document.IsUint64();
    }

    bool isDouble() const
    {
        return m_document.IsDouble();
    }

    bool isString() const
    {
        return m_document.IsString();
    }

    bool isArray() const
    {
        return m_document.IsArray();
    }

    bool isObject() const
    {
        return m_document.IsObject();
    }

    std::string typeName() const
    {
        switch (m_document.GetType())
        {
            case rapidjson::kNullType: return "null";
            case rapidjson::kFalseType:
            case rapidjson::kTrueType: return "bool";
            case rapidjson::kObjectType: return "object";
            case rapidjson::kArrayType: return "array";
            case rapidjson::kStringType: return "string";
            case rapidjson::kNumberType: return "number";
            default: return "unknown";
        }
    }

    bool getBool() const
    {
        return m_document.GetBool();
    }

    int getInt() const
    {
        return m_document.GetInt();
    }

    unsigned int getUint() const
    {
        return m_document.GetUint();
    }

    int64_t getInt64() const
    {
        return m_document.GetInt64();
    }

    uint64_t getUint64() const
    {
        return m_document.GetUint64();
    }

    double getDouble() const
    {
        return m_document.GetDouble();
    }

    std::string getString() const
    {
        return m_document.GetString();
    }

    std::vector<Json> getArray() const
    {
        std::vector<Json> array;
        std::transform(m_document.GetArray().Begin(),
                       m_document.GetArray().End(),
                       std::back_inserter(array),
                       [](const rapidjson::Value& value)
                       { return Json(value); });

        return array;
    }

    std::vector<std::tuple<std::string, Json>> getObject() const
    {
        std::vector<std::tuple<std::string, Json>> object;

        for (auto& [key, value] : m_document.GetObject())
        {
            object.emplace_back(std::make_pair(key.GetString(), Json(value)));
        }

        return object;
    }
};

#endif // _JSON_H
