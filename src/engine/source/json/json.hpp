#ifndef _JSON_H
#define _JSON_H

#include <algorithm>
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

namespace json
{

class Json
{
private:
    rapidjson::Document m_document;

    /**
     * @brief Construct a new Json object form a rapidjason::Value.
     * Copies the value.
     *
     * @param value The rapidjson::Value to copy.
     */
    Json(const rapidjson::Value& value)
    {
        m_document.CopyFrom(value, m_document.GetAllocator());
    }

    /**
     * @brief Construct a new Json object form a rapidjason::GenericObject.
     * Copies the object.
     *
     * @param object The rapidjson::GenericObject to copy.
     */
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
    /**
     * @brief Construct a new Json empty json object.
     *
     */
    Json() = default;

    /**
     * @brief Construct a new Json object from a rapidjason Document.
     * Moves the document.
     *
     * @param document The rapidjson::Document to move.
     */
    explicit Json(rapidjson::Document&& document)
        : m_document(std::move(document))
    {
    }

    /**
     * @brief Construct a new Json object from a json string
     *
     * @param json The json string to parse.
     */
    explicit Json(const char* json)
    {
        rapidjson::ParseResult result = m_document.Parse(json);
        if (!result)
        {
            throw std::runtime_error(fmt::format(
                "[Json(jsonString)] Unable to build json document because: {} at {}",
                rapidjson::GetParseError_En(result.Code()),
                result.Offset()));
        }
    }

    /**
     * @brief Copy constructs a new Json object.
     * Value is copied.
     *
     * @param other The Json to copy.
     */
    Json(const Json& other)
    {
        m_document.CopyFrom(other.m_document, m_document.GetAllocator());
    }

    /**
     * @brief Copy assignment operator.
     * Value is copied.
     *
     * @param other The Json to copy.
     * @return Json& The new Json object.
     */
    Json& operator=(const Json& other)
    {
        m_document.CopyFrom(other.m_document, m_document.GetAllocator());
        return *this;
    }

    /************************************************************************************/
    // Static Helpers
    /************************************************************************************/

    /**
     * @brief Transform dot path string to pointer path string.
     *
     * @param dotPath The dot path string.
     * @return std::string The pointer path string.
     */
    static std::string formatJsonPath(std::string_view dotPath)
    {
        // TODO: Handle array indices and pointer path operators.
        std::string pointerPath {dotPath};
        std::replace(std::begin(pointerPath), std::end(pointerPath), '.', '/');
        if (pointerPath.front() != '/')
        {
            pointerPath.insert(0, "/");
        }

        return pointerPath;
    }

    /************************************************************************************/
    // Runtime functionality, used only by our operations.
    // TODO: Move runtime functionality to separate class.
    /************************************************************************************/

    /**
     * @brief Move copy constructor.
     * Value is moved.
     *
     * @param other The Json to move, which is left in an empty state.
     */
    Json(Json&& other) noexcept
        : m_document {std::move(other.m_document)}
    {
    }

    /**
     * @brief Move copy assignment operator.
     * Value is moved.
     *
     * @param other The Json to move, which is left in an empty state.
     * @return Json& The new Json object.
     */
    Json& operator=(Json&& other) noexcept
    {
        m_document = std::move(other.m_document);
        return *this;
    }

    /**
     * @brief Check if the Json contains a field with the given pointer path.
     *
     * @param pointerPath The pointer path to check.
     * @return true The Json contains the field.
     * @return false The Json does not contain the field.
     *
     * @throws std::runtime_error If the pointer path is invalid.
     */
    bool exists(std::string_view pointerPath) const
    {
        auto fieldPtr = rapidjson::Pointer(pointerPath.data());
        if (fieldPtr.IsValid())
        {
            return fieldPtr.Get(m_document) != nullptr;
        }
        else
        {
            throw std::runtime_error(fmt::format(
                "[Json::exists(pointerPath)] Invalid pointerPath: [{}]", pointerPath));
        }
    }

    /**
     * @brief Check if the Json contains a field with the given dot path, and if so, with
     * the given value.
     *
     * @param pointerPath
     * @param value
     * @return true The Json contains the field with the given value.
     * @return false The Json does not contain the field with the given value.
     *
     * @throws std::runtime_error If the pointer path is invalid.
     */
    bool equals(std::string_view pointerPath, const Json& value) const
    {
        auto fieldPtr = rapidjson::Pointer(pointerPath.data());
        if (fieldPtr.IsValid())
        {
            const auto got = fieldPtr.Get(m_document);
            return (got && *got == value.m_document);
        }
        else
        {
            throw std::runtime_error(fmt::format(
                "[Json::equals(pointerPath, value)] Invalid pointerPath: [{}]",
                pointerPath));
        }
    }

    /**
     * @brief Check if basePointerPath field's value is equal to referencePointerPath
     * field's value. If basePointerPath or referencePointerPath is not found, returns
     * false.
     *
     * @param basePointerPath The base pointer path to check.
     * @param referencePointerPath The reference pointer path to check.
     * @return true The base field's value is equal to the reference field's value.
     * @return false The base field's value is not equal to the reference field's value.
     *
     * @throws std::runtime_error If any pointer path is invalid.
     */
    bool equals(std::string_view basePointerPath,
                std::string_view referencePointerPath) const
    {
        auto fieldPtr = rapidjson::Pointer(basePointerPath.data());
        auto referencePtr = rapidjson::Pointer(referencePointerPath.data());

        if (fieldPtr.IsValid() && referencePtr.IsValid())
        {
            const auto got = fieldPtr.Get(m_document);
            const auto reference = referencePtr.Get(m_document);
            return (got && reference && *got == *reference);
        }
        else
        {
            throw std::runtime_error(
                fmt::format("[Json::equals(basePointerPath, referencePointerPath)] "
                            "Invalid json path: [{}] or [{}]",
                            basePointerPath,
                            referencePointerPath));
        }
    }

    /**
     * @brief Set the value of the field with the given pointer path.
     * Overwrites previous value.
     *
     * @param pointerPath The pointer path to set.
     * @param value The value to set.
     *
     * @throws std::runtime_error If the pointer path is invalid.
     */
    void set(std::string_view pointerPath, const Json& value)
    {
        auto fieldPtr = rapidjson::Pointer(pointerPath.data());
        if (fieldPtr.IsValid())
        {
            fieldPtr.Set(m_document, value.m_document);
        }
        else
        {
            throw std::runtime_error(
                fmt::format("[Json::set(pointerPath, value)] Invalid pointerPath: [{}]",
                            pointerPath));
        }
    }

    /**
     * @brief Set the value of the base field with the value of the reference field.
     * Overwrites previous value. If reference field is not found, sets base field to
     * null.
     *
     * @param basePointerPath The base pointer path to set.
     * @param referencePointerPath The reference pointer path.
     *
     * @throws std::runtime_error If any pointer path is invalid.
     */
    void set(std::string_view basePointerPath, std::string_view referencePointerPath)
    {
        auto fieldPtr = rapidjson::Pointer(basePointerPath.data());
        auto referencePtr = rapidjson::Pointer(referencePointerPath.data());

        if (fieldPtr.IsValid() && referencePtr.IsValid())
        {
            const auto* reference = referencePtr.Get(m_document);
            if (reference)
            {
                fieldPtr.Set(m_document, *reference);
            }
            else
            {
                fieldPtr.Set(m_document, rapidjson::Value());
            }
        }
        else
        {
            throw std::runtime_error(
                fmt::format("[Json::set(basePointerPath, referencePointerPath)] "
                            "Invalid json path: [{}] or [{}]",
                            basePointerPath,
                            referencePointerPath));
        }
    }

    /**
     * @brief get the value of the string field.
     * Overwrites previous value. If reference field is not found, sets base field to
     * null.
     *
     * @param basePointerPath The base pointer path to set.
     *
     * @return T The value of the field.
     *
     * @throws std::runtime_error If any pointer path is invalid.
     */
    std::optional<std::string> getValueString(std::string_view basePointerPath)
    {
        auto fieldPtr = rapidjson::Pointer(basePointerPath.data());

        if (fieldPtr.IsValid())
        {
            const auto* value = fieldPtr.Get(m_document);
            if(value && value->IsString())
            {
                return value->GetString();
            }
            else
            {
                return std::nullopt;
            }
        }
        else
        {
            throw std::runtime_error(
                fmt::format("[Json::get(basePointerPath)] "
                            "Invalid json path: [{}]",
                            basePointerPath));
        }
    }

    /**
     * @brief get the value of the int field.
     * Overwrites previous value. If reference field is not found, sets base field to
     * null.
     *
     * @param basePointerPath The base pointer path to set.
     *
     * @return T The value of the field.
     *
     * @throws std::runtime_error If any pointer path is invalid.
     */
    std::optional<int> getValueInt(std::string_view basePointerPath)
    {
        auto fieldPtr = rapidjson::Pointer(basePointerPath.data());

        if (fieldPtr.IsValid())
        {
            const auto* value = fieldPtr.Get(m_document);
            if(value && value->IsInt())
            {
                return value->GetInt();
            }
            else
            {
                return std::nullopt;
            }
        }
        else
        {
            throw std::runtime_error(
                fmt::format("[Json::get(basePointerPath)] "
                            "Invalid json path: [{}]",
                            basePointerPath));
        }
    }

    /**
     * @brief get the value of the double field.
     * Overwrites previous value. If reference field is not found, sets base field to
     * null.
     *
     * @param basePointerPath The base pointer path to set.
     *
     * @return T The value of the field.
     *
     * @throws std::runtime_error If any pointer path is invalid.
     */
    std::optional<double> getValueDouble(std::string_view basePointerPath)
    {
        auto fieldPtr = rapidjson::Pointer(basePointerPath.data());

        if (fieldPtr.IsValid())
        {
            const auto* value = fieldPtr.Get(m_document);
            if(value && value->IsDouble())
            {
                return value->GetDouble();
            }
            else
            {
                return std::nullopt;
            }
        }
        else
        {
            throw std::runtime_error(
                fmt::format("[Json::get(basePointerPath)] "
                            "Invalid json path: [{}]",
                            basePointerPath));
        }
    }

    /**
     * @brief get the value of the bool field.
     * Overwrites previous value. If reference field is not found, sets base field to
     * null.
     *
     * @param basePointerPath The base pointer path to set.
     *
     * @return T The value of the field.
     *
     * @throws std::runtime_error If any pointer path is invalid.
     */
    std::optional<bool> getValueBool(std::string_view basePointerPath)
    {
        auto fieldPtr = rapidjson::Pointer(basePointerPath.data());

        if (fieldPtr.IsValid())
        {
            const auto* value = fieldPtr.Get(m_document);
            if(value && value->IsBool())
            {
                return value->GetBool();
            }
            else
            {
                return std::nullopt;
            }
        }
        else
        {
            throw std::runtime_error(
                fmt::format("[Json::get(basePointerPath)] "
                            "Invalid json path: [{}]",
                            basePointerPath));
        }
    }

    std::optional<std::string> getAsString(std::string_view basePointerPath)
    {
        auto fieldPtr = rapidjson::Pointer(basePointerPath.data());

        if (fieldPtr.IsValid())
        {
            const auto* value = fieldPtr.Get(m_document);
            if(value)
            {
                return value->GetString();
            }
            else
            {
                return std::nullopt;
            }
        }
        else
        {
            throw std::runtime_error(
                fmt::format("[Json::get(basePointerPath)] "
                            "Invalid json path: [{}]",
                            basePointerPath));
        }
    }

    /**
     * @brief Get Json prettyfied string.
     *
     * @return std::string The Json prettyfied string.
     */
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

    /**
     * @brief Get Json string.
     *
     * @return std::string The Json string.
     */
    std::string str() const
    {
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer,
                          rapidjson::Document::EncodingType,
                          rapidjson::ASCII<>>
            writer(buffer);
        this->m_document.Accept(writer);
        return buffer.GetString();
    }

    friend std::ostream& operator<<(std::ostream& os, const Json& json)
    {
        os << json.str();
        return os;
    }

    /************************************************************************************/
    // Buildtime functionality, used outside operation's runtime.
    // TODO: Move non-buildtime functionality to a separate class.
    /************************************************************************************/

    /**
     * @brief Get number of elements.
     * If array get number of elements. If object get number of pairs (key, value).
     *
     * @return size_t The number of elements.
     *
     * @throws std::runtime_error If the Json is not an array or object.
     */
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
                "[Json::size()] Expected array or object, got: {}", typeName()));
        }
    }

    /**
     * @brief Check if the Json is null value.
     *
     * @return true The Json is null value.
     * @return false The Json is not null value.
     */
    bool isNull() const
    {
        return m_document.IsNull();
    }

    /**
     * @brief Check if the Json is boolean value.
     *
     * @return true The Json is boolean value.
     * @return false The Json is not boolean value.
     */
    bool isBool() const
    {
        return m_document.IsBool();
    }

    /**
     * @brief Check if the Json is number value.
     *
     * @return true The Json is number value.
     * @return false The Json is not number value.
     */
    bool isNumber() const
    {
        return m_document.IsNumber();
    }

    /**
     * @brief Check if the Json is string value.
     *
     * @return true The Json is string value.
     * @return false The Json is not string value.
     */
    bool isString() const
    {
        return m_document.IsString();
    }

    /**
     * @brief Check if the Json is array value.
     *
     * @return true The Json is array value.
     * @return false The Json is not array value.
     */
    bool isArray() const
    {
        return m_document.IsArray();
    }

    /**
     * @brief Check if the Json is object value.
     *
     * @return true The Json is object value.
     * @return false The Json is not object value.
     */
    bool isObject() const
    {
        return m_document.IsObject();
    }

    /**
     * @brief Get the type name of the Json.
     *
     * @return std::string The type name of the Json.
     */
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

    /**
     * @brief Get the Json value as a boolean.
     *
     * @return bool The Json value as a boolean.
     *
     * @throws std::runtime_error If the Json is not a boolean.
     */
    bool getBool() const
    {
        return m_document.GetBool();
    }

    /**
     * @brief Get the Json value as an Int number.
     *
     * @return int The Json value as an Int number.
     *
     * @throws std::runtime_error If the Json is not a number.
     */
    int getInt() const
    {
        return m_document.GetInt();
    }

    /**
     * @brief Get the Json value as a Double number.
     *
     * @return double The Json value as a Double number.
     *
     * @throws std::runtime_error If the Json is not a number.
     */
    double getDouble() const
    {
        return m_document.GetDouble();
    }

    /**
     * @brief Get the Json value as a string.
     *
     * @return std::string The Json value as a string.
     *
     * @throws std::runtime_error If the Json is not a string.
     */
    std::string getString() const
    {
        return m_document.GetString();
    }

    /**
     * @brief Get the Json value as a vector<Json>.
     * Copy the Json array to a vector<Json>.
     *
     * @return std::vector<Json> The Json value as a vector<Json>.
     *
     * @throws std::runtime_error If the Json is not an array.
     */
    std::vector<Json> getArray() const
    {
        // TODO: Make a non copy version of get array.
        std::vector<Json> array;
        std::transform(m_document.GetArray().Begin(),
                       m_document.GetArray().End(),
                       std::back_inserter(array),
                       [](const rapidjson::Value& value) { return Json(value); });

        return array;
    }

    /**
     * @brief Get the Json value as an object in the form vector<tuple<std::string,
     * Json>>. Copy the Json object to a vector<tuple<std::string, Json>>. This
     * representation is used to preserve the order of the keys.
     *
     * @return std::vector<std::tuple<std::string, Json>>
     *
     * @throws std::runtime_error If the Json is not an object.
     */
    std::vector<std::tuple<std::string, Json>> getObject() const
    {
        // TODO: Make a non copy version of get object.
        std::vector<std::tuple<std::string, Json>> object;

        for (auto& [key, value] : m_document.GetObject())
        {
            object.emplace_back(std::make_pair(key.GetString(), Json(value)));
        }

        return object;
    }

    // Required by parser
    void setNull()
    {
        m_document.SetNull();
    }

    void setBool(bool value)
    {
        m_document.SetBool(value);
    }

    void setInt(int value)
    {
        m_document.SetInt(value);
    }

    void setDouble(double value)
    {
        m_document.SetDouble(value);
    }

    void setString(const std::string& value)
    {
        m_document.SetString(value.c_str(), m_document.GetAllocator());
    }
};

} // namespace json

#endif // _JSON_H
