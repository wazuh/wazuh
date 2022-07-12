#ifndef _JSON_H
#define _JSON_H

#include <algorithm>
#include <optional>
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

        // TODO: This should be checked by the library, or make a better validator.
        // As stated in rapidjson docs, if an object contains duplicated memebers,
        // equality comparator always returns false, for said member or for the whole
        // object if it contains duplicated members.

        // If equality between a member and itself is false, then it is a duplicate or
        // contains duplicated members.
        auto validateDuplicatedKeys = [](const rapidjson::Value& value,
                                         auto& recurRef) -> void
        {
            if (value.IsObject())
            {
                for (auto it = value.MemberBegin(); it != value.MemberEnd(); ++it)
                {
                    if (value[it->name.GetString()] != value[it->name.GetString()])
                    {
                        throw std::runtime_error(fmt::format(
                            "[Json(jsonString)] Unable to build json "
                            "document because: Duplicated key, or inside [{}]",
                            it->name.GetString()));
                    }

                    recurRef(it->value, recurRef);
                }
            }
        };

        validateDuplicatedKeys(m_document, validateDuplicatedKeys);
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

    bool operator==(const Json& other) const
    {
        return m_document == other.m_document;
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

    /************************************************************************************/
    // Getters
    /************************************************************************************/

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
    std::optional<std::string> getString(std::string_view path = "") const
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            const auto* value = pp.Get(m_document);
            if (value && value->IsString())
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
            throw std::runtime_error(fmt::format("[Json::get(path)] "
                                                 "Invalid json path: [{}]",
                                                 path));
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
    std::optional<int> getInt(std::string_view path = "") const
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            const auto* value = pp.Get(m_document);
            if (value && value->IsInt())
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
            throw std::runtime_error(fmt::format("[Json::get(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
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
    std::optional<double> getDouble(std::string_view path = "") const
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            const auto* value = pp.Get(m_document);
            if (value && value->IsDouble())
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
            throw std::runtime_error(fmt::format("[Json::get(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
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
    std::optional<bool> getBool(std::string_view path = "") const
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            const auto* value = pp.Get(m_document);
            if (value && value->IsBool())
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
            throw std::runtime_error(fmt::format("[Json::get(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
        }
    }

    std::optional<std::vector<Json>> getArray(std::string_view path = "") const
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            const auto* value = pp.Get(m_document);
            if (value && value->IsArray())
            {
                std::vector<Json> result;
                for (const auto& item : value->GetArray())
                {
                    result.push_back(Json(item));
                }
                return result;
            }
            else
            {
                return std::nullopt;
            }
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::get(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
        }
    }

    std::optional<std::vector<std::tuple<std::string, Json>>>
    getObject(std::string_view path = "") const
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            const auto* value = pp.Get(m_document);
            if (value && value->IsObject())
            {
                std::vector<std::tuple<std::string, Json>> result;
                for (auto& [key, value] : value->GetObject())
                {
                    result.emplace_back(std::make_tuple(key.GetString(), Json(value)));
                }
                return result;
            }
            else
            {
                return std::nullopt;
            }
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::get(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
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
    // Query
    /************************************************************************************/

    /**
     * @brief Get number of elements.
     * If array get number of elements. If object get number of pairs (key, value).
     *
     * @return size_t The number of elements.
     *
     * @throws std::runtime_error If the Json is not an array or object.
     */
    size_t size(std::string_view path = "") const
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            const auto* value = pp.Get(m_document);
            if (value)
            {
                if (value->IsArray())
                {
                    return value->Size();
                }
                else if (value->IsObject())
                {
                    return value->MemberCount();
                }
                else
                {
                    throw std::runtime_error(fmt::format("[Json::size(basePointerPath)] "
                                                         "Invalid json path: [{}]",
                                                         path));
                }
            }
            else
            {
                throw std::runtime_error(fmt::format("[Json::size(basePointerPath)] "
                                                     "Cannot find json path: [{}]",
                                                     path));
            }
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::size(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
        }
    }

    /**
     * @brief Check if the Json described by the path is Null.
     *
     * Ensure that the path exists before calling this function.
     *
     *
     * @param path The path to the object, default value is root object ("").
     * @return true if Json is Null.
     * @return false if Json is not Null.
     *
     * @throws std::runtime_error If path is invalid or cannot be found.
     */
    bool isNull(std::string_view path = "") const
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            const auto* value = pp.Get(m_document);
            if (value)
            {
                return value->IsNull();
            }
            else
            {
                throw std::runtime_error(fmt::format("[Json::isNull(basePointerPath)] "
                                                     "Cannot find path: [{}]",
                                                     path));
            }
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::isNull(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
        }
    }

    /**
     * @brief Check if the Json described by the path is Bool.
     *
     * Ensure that the path exists before calling this function.
     *
     *
     * @param path The path to the object, default value is root object ("").
     * @return true if Json is Bool.
     * @return false if Json is not Bool.
     *
     * @throws std::runtime_error If path is invalid or cannot be found.
     */
    bool isBool(std::string_view path = "") const
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            const auto* value = pp.Get(m_document);
            if (value)
            {
                return value->IsBool();
            }
            else
            {
                throw std::runtime_error(fmt::format("[Json::isBool(basePointerPath)] "
                                                     "Cannot find path: [{}]",
                                                     path));
            }
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::isBool(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
        }
    }

    /**
     * @brief Check if the Json described by the path is Number.
     *
     * Ensure that the path exists before calling this function.
     *
     *
     * @param path The path to the object, default value is root object ("").
     * @return true if Json is Number.
     * @return false if Json is not Number.
     *
     * @throws std::runtime_error If path is invalid or cannot be found.
     */
    bool isNumber(std::string_view path = "") const
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            const auto* value = pp.Get(m_document);
            if (value)
            {
                return value->IsNumber();
            }
            else
            {
                throw std::runtime_error(fmt::format("[Json::isNumber(basePointerPath)] "
                                                     "Cannot find path: [{}]",
                                                     path));
            }
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::isNumber(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
        }
    }

    /**
     * @brief Check if the Json described by the path is String.
     *
     * Ensure that the path exists before calling this function.
     *
     *
     * @param path The path to the object, default value is root object ("").
     * @return true if Json is String.
     * @return false if Json is not String.
     *
     * @throws std::runtime_error If path is invalid or cannot be found.
     */
    bool isString(std::string_view path = "") const
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            const auto* value = pp.Get(m_document);
            if (value)
            {
                return value->IsString();
            }
            else
            {
                throw std::runtime_error(fmt::format("[Json::isString(basePointerPath)] "
                                                     "Cannot find path: [{}]",
                                                     path));
            }
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::isString(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
        }
    }

    /**
     * @brief Check if the Json described by the path is Array.
     *
     * Ensure that the path exists before calling this function.
     *
     *
     * @param path The path to the object, default value is root object ("").
     * @return true if Json is Array.
     * @return false if Json is not Array.
     *
     * @throws std::runtime_error If path is invalid or cannot be found.
     */
    bool isArray(std::string_view path = "") const
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            const auto* value = pp.Get(m_document);
            if (value)
            {
                return value->IsArray();
            }
            else
            {
                throw std::runtime_error(fmt::format("[Json::isArray(basePointerPath)] "
                                                     "Cannot find path: [{}]",
                                                     path));
            }
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::isArray(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
        }
    }

    /**
     * @brief Check if the Json described by the path is Object.
     *
     * Ensure that the path exists before calling this function.
     *
     *
     * @param path The path to the object, default value is root object ("").
     * @return true if Json is Object.
     * @return false if Json is not Object.
     *
     * @throws std::runtime_error If path is invalid or cannot be found.
     */
    bool isObject(std::string_view path = "") const
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            const auto* value = pp.Get(m_document);
            if (value)
            {
                return value->IsObject();
            }
            else
            {
                throw std::runtime_error(fmt::format("[Json::isObject(basePointerPath)] "
                                                     "Cannot find path: [{}]",
                                                     path));
            }
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::isObject(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
        }
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

    /************************************************************************************/
    // Setters
    /************************************************************************************/

    /**
     * @brief Set the Null object at the path.
     * Parents objects are created if they do not exist.
     *
     * @param path The path to the object, default value is root object ("").
     *
     * @throws std::runtime_error If path is invalid.
     */
    void setNull(std::string_view path = "")
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            pp.Set(m_document, rapidjson::Value().SetNull());
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::setNull(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
        }
    }

    /**
     * @brief Set the Boolean object at the path.
     * Parents objects are created if they do not exist.
     *
     * @param value The value to set.
     * @param path The path to the object, default value is root object ("").
     *
     * @throws std::runtime_error If path is invalid.
     */
    void setBool(bool value, std::string_view path = "")
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            pp.Set(m_document, value);
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::setBool(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
        }
    }

    /**
     * @brief Set the Integer object at the path.
     * Parents objects are created if they do not exist.
     *
     * @param value The value to set.
     * @param path The path to the object, default value is root object ("").
     *
     * @throws std::runtime_error If path is invalid.
     */
    void setInt(int value, std::string_view path = "")
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            pp.Set(m_document, value);
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::setInt(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
        }
    }

    /**
     * @brief Set the Double object at the path.
     * Parents objects are created if they do not exist.
     *
     * @param value The value to set.
     * @param path The path to the object, default value is root object ("").
     *
     * @throws std::runtime_error If path is invalid.
     */
    void setDouble(double value, std::string_view path = "")
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            pp.Set(m_document, value);
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::setDouble(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
        }
    }

    /**
     * @brief Set the String object at the path.
     * Parents objects are created if they do not exist.
     *
     * @param value The value to set.
     * @param path The path to the object, default value is root object ("").
     *
     * @throws std::runtime_error If path is invalid.
     */
    void setString(std::string_view value, std::string_view path = "")
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            pp.Set(m_document, value.data());
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::setString(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
        }
    }

    /**
     * @brief Set the Array object at the path.
     * Parents objects are created if they do not exist.
     *
     * @param path The path to the object, default value is root object ("").
     *
     * @throws std::runtime_error If path is invalid.
     */
    void setArray(std::string_view path = "")
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            pp.Set(m_document, rapidjson::Value().SetArray());
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::setArray(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
        }
    }

    /**
     * @brief Set the Object object at the path.
     * Parents objects are created if they do not exist.
     *
     * @param path The path to the object, default value is root object ("").
     *
     * @throws std::runtime_error If path is invalid.
     */
    void setObject(std::string_view path = "")
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            pp.Set(m_document, rapidjson::Value().SetObject());
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::setObject(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
        }
    }

    /**
     * @brief Append string to the Array object at the path.
     * Parents objects are created if they do not exist.
     * If the object is not an Array, it is converted to an Array.
     *
     * @param value The string to append.
     *
     * @throws std::runtime_error If path is invalid.
     */
    void appendString(std::string_view value, std::string_view path = "")
    {
        auto pp = rapidjson::Pointer(path.data());

        if (pp.IsValid())
        {
            // TODO: not sure if needed, add test
            const rapidjson::size_t s1 = static_cast<rapidjson::size_t>(value.size());
            const size_t s2 = static_cast<size_t>(s1);
            if (s2 != value.size())
            {
                throw std::runtime_error(
                    fmt::format("[Json::appendString(basePointerPath)] "
                                "String is too long: [{}]",
                                value));
            }
            rapidjson::Value v(value.data(), s2, m_document.GetAllocator());

            auto* val = pp.Get(m_document);
            if (val)
            {
                if (!val->IsArray())
                {
                    val->SetArray();
                }

                val->PushBack(v, m_document.GetAllocator());
            }
            else
            {
                rapidjson::Value vArray;
                vArray.SetArray();
                vArray.PushBack(v, m_document.GetAllocator());
                pp.Set(m_document, vArray);
            }
        }
        else
        {
            throw std::runtime_error(fmt::format("[Json::appendString(basePointerPath)] "
                                                 "Invalid json path: [{}]",
                                                 path));
        }
    }

    /**
     * @brief Erase Json object at the path.
     *
     * @param path The path to the object, default value is root object ("").
     * @return true if object was erased, false if object was not found.
     *
     * @throws std::runtime_error If path is invalid.
     */
    bool erase(std::string_view path = "")
    {
        if (path.empty())
        {
            m_document.SetNull();
            return true;
        }
        else
        {
            auto pp = rapidjson::Pointer(path.data());

            if (pp.IsValid())
            {
                return pp.Erase(m_document);
            }
            else
            {
                throw std::runtime_error(fmt::format("[Json::erase(basePointerPath)] "
                                                     "Invalid json path: [{}]",
                                                     path));
            }
        }
    }
};

} // namespace json

#endif // _JSON_H
