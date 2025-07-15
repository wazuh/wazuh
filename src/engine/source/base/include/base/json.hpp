#ifndef _JSON_H
#define _JSON_H

#include <algorithm>
#include <cmath>
#include <functional>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/pointer.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <base/error.hpp>

namespace json
{

constexpr bool RECURSIVE {true};
constexpr bool NOT_RECURSIVE {false};

class Json
{
public:
    enum class Type
    {
        Null,
        Object,
        Array,
        String,
        Number,
        Boolean,
        Unknow
    };

    friend std::ostream& operator<<(std::ostream& os, Type type)
    {
        switch (type)
        {
            case Type::Null: os << "null"; break;
            case Type::Object: os << "object"; break;
            case Type::Array: os << "array"; break;
            case Type::String: os << "string"; break;
            case Type::Number: os << "number"; break;
            case Type::Boolean: os << "boolean"; break;
        }

        return os;
    }

    static constexpr auto typeToStr(Type type)
    {
        switch (type)
        {
            case Type::Null: return "null";
            case Type::Object: return "object";
            case Type::Array: return "array";
            case Type::String: return "string";
            case Type::Number: return "number";
            case Type::Boolean: return "boolean";
            default: return "unknown";
        }
    }

    static constexpr Type strToType(const char* str)
    {
        if (strcmp(str, "null") == 0)
        {
            return Type::Null;
        }
        else if (strcmp(str, "object") == 0)
        {
            return Type::Object;
        }
        else if (strcmp(str, "array") == 0)
        {
            return Type::Array;
        }
        else if (strcmp(str, "string") == 0)
        {
            return Type::String;
        }
        else if (strcmp(str, "number") == 0)
        {
            return Type::Number;
        }
        else if (strcmp(str, "boolean") == 0)
        {
            return Type::Boolean;
        }
        else
        {
            throw std::runtime_error("Unknown type");
        }
    }

private:
    rapidjson::Document m_document;

    /**
     * @brief Construct a new Json object form a rapidjason::Value.
     * Copies the value.
     *
     * @param value The rapidjson::Value to copy.
     */
    Json(const rapidjson::Value& value);

    /**
     * @brief Construct a new Json object form a rapidjason::GenericObject.
     * Copies the object.
     *
     * @param object The rapidjson::GenericObject to copy.
     */
    Json(const rapidjson::GenericObject<true, rapidjson::Value>& object);

    /**
     * @brief Get Json type from internal rapidjason type.
     *
     * @param t rapidjson::Type to convert.
     * @return constexpr Type The converted type.
     *
     * @throw std::runtime_error if the type is not supported.
     */
    constexpr static Type rapidTypeToJsonType(rapidjson::Type t)
    {
        switch (t)
        {
            case rapidjson::kNullType: return Type::Null;
            case rapidjson::kObjectType: return Type::Object;
            case rapidjson::kArrayType: return Type::Array;
            case rapidjson::kStringType: return Type::String;
            case rapidjson::kNumberType: return Type::Number;
            case rapidjson::kFalseType:
            case rapidjson::kTrueType: return Type::Boolean;
            default: throw std::runtime_error("Unknown rapidjson::Type");
        }
    }

    void merge(const bool isRecursive, const rapidjson::Value& source, std::string_view path);

public:
    /**
     * @brief Construct a new Json empty json object.
     *
     */
    Json();

    /**
     * @brief Construct a new Json object from a rapidjason Document.
     * Moves the document.
     *
     * @param document The rapidjson::Document to move.
     */
    explicit Json(rapidjson::Document&& document);

    /**
     * @brief Construct a new Json object from a json string
     *
     * @param json The json string to parse.
     */
    explicit Json(const char* json);

    /**
     * @brief Copy constructs a new Json object.
     * Value is copied.
     *
     * @param other The Json to copy.
     */
    Json(const Json& other);

    /**
     * @brief Copy assignment operator.
     * Value is copied.
     *
     * @param other The Json to copy.
     * @return Json& The new Json object.
     */
    Json& operator=(const Json& other) = delete;

    friend bool operator==(const Json& lhs, const Json& rhs) { return lhs.m_document == rhs.m_document; }

    friend bool operator!=(const Json& lhs, const Json& rhs) { return !(lhs == rhs); }

    /************************************************************************************/
    // Static Helpers
    /************************************************************************************/

    /**
     * @brief Transform dot path string to pointer path string.
     *
     * @param dotPath The dot path string.
     * @return std::string The pointer path string.
     */
    static std::string formatJsonPath(std::string_view dotPath, bool skipDot = false);

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
    Json(Json&& other) noexcept;

    /**
     * @brief Move copy assignment operator.
     * Value is moved.
     *
     * @param other The Json to move, which is left in an empty state.
     * @return Json& The new Json object.
     */
    Json& operator=(Json&& other) noexcept;

    /**
     * @brief Check if the Json contains a field with the given pointer path.
     *
     * @param pointerPath The pointer path to check.
     * @return true The Json contains the field.
     * @return false The Json does not contain the field.
     *
     * @throws std::runtime_error If the pointer path is invalid.
     */
    bool exists(std::string_view pointerPath) const;

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
    bool equals(std::string_view pointerPath, const Json& value) const;

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
    bool equals(std::string_view basePointerPath, std::string_view referencePointerPath) const;

    /**
     * @brief Set the value of the field with the given pointer path.
     * Overwrites previous value.
     *
     * @param pointerPath The pointer path to set.
     * @param value The value to set.
     *
     * @throws std::runtime_error If the pointer path is invalid.
     */
    void set(std::string_view pointerPath, const Json& value);

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
    void set(std::string_view basePointerPath, std::string_view referencePointerPath);

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
    std::optional<std::string> getString(std::string_view path = "") const;

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
    std::optional<int> getInt(std::string_view path = "") const;

    /**
     * @brief get the value of the int64 field.
     * Overwrites previous value. If reference field is not found, sets base field to
     * null.
     *
     * @param basePointerPath The base pointer path to set.
     *
     * @return T The value of the field.
     *
     * @throws std::runtime_error If any pointer path is invalid.
     */
    std::optional<int64_t> getInt64(std::string_view path = "") const;

    /**
     * @brief Get the value of the int or int64 field as int64.
     *
     * @param path The path to the field.
     * @return std::optional<int64_t> The value of the field or nothing if the path not found.
     * @throws std::runtime_error If the path is invalid.
     */
    std::optional<int64_t> getIntAsInt64(std::string_view path = "") const;

    /**
     * @brief get the value of the float field.
     * Overwrites previous value. If reference field is not found, sets base field to
     * null.
     *
     * @param basePointerPath The base pointer path to set.
     *
     * @return T The value of the field.
     *
     * @throws std::runtime_error If any pointer path is invalid.
     */
    std::optional<float_t> getFloat(std::string_view path = "") const;

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
    std::optional<double_t> getDouble(std::string_view path = "") const;

    /**
     * @brief get the value of either a double or int field as a double.
     * Overwrites previous value. If reference field is not found, sets base field to
     * null.
     *
     * @param basePointerPath The base pointer path to set.
     *
     * @return T The value of the field.
     *
     * @throws std::runtime_error If any pointer path is invalid.
     *
     * @todo Develop tests for this method
     */
    std::optional<double> getNumberAsDouble(std::string_view path = "") const;

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
    std::optional<bool> getBool(std::string_view path = "") const;

    /**
     * @brief get the value of the array field.
     * Overwrites previous value. If reference field is not found, sets base field to
     * null.
     *
     * @param basePointerPath The base pointer path to set.
     *
     * @return T The value of the field.
     *
     * @throws std::runtime_error If any pointer path is invalid.
     */
    std::optional<std::vector<Json>> getArray(std::string_view path = "") const;

    /**
     * @brief get the value of the object field.
     *
     * @param path The base pointer path to get.
     *
     * @return T The value of the field.
     *
     * @throws std::runtime_error If any pointer path is invalid.
     */
    std::optional<std::vector<std::tuple<std::string, Json>>> getObject(std::string_view path = "") const;

    /**
     * @brief Get a list of fields from a json object.
     *
     * @return std::optional<std::vector<std::string>> The list of fields or nothing if the Json is not an object.
     */
    std::optional<std::vector<std::string>> getFields() const;

    /**
     * @brief Get Json prettyfied string.
     *
     * @return std::string The Json prettyfied string.
     */
    std::string prettyStr() const;

    /**
     * @brief Get Json string.
     *
     * @return std::string The Json string.
     */
    std::string str() const;

    /**
     * @brief Get Json string from an object.
     *
     * @param path The path to the object.
     * @return std::string The Json string or nothing if the path not found.
     * @throws std::runtime_error If the path is invalid.
     */
    std::optional<std::string> str(std::string_view path) const;

    /**
     * @brief Get a copy of the Json object or nothing if the path not found.c++ diagram
     *
     * @param path The path to the object, default value is root object ("").
     * @return std::optional<Json> The Json object if it exists, std::nullopt otherwise.
     * @throw std::runtime_error If path is invalid.
     */
    std::optional<Json> getJson(std::string_view path = "") const;

    friend std::ostream& operator<<(std::ostream& os, const Json& json);

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
    size_t size(std::string_view path = "") const;

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
    bool isNull(std::string_view path = "") const;

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
    bool isBool(std::string_view path = "") const;

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
    bool isNumber(std::string_view path = "") const;

    /**
     * @brief Check if the Json described by the path is integer.
     *
     * Ensure that the path exists before calling this function.
     *
     *
     * @param path The path to the object, default value is root object ("").
     * @return true if Json is Int.
     * @return false if Json is not Int.
     *
     * @throws std::runtime_error If path is invalid or cannot be found.
     */
    bool isInt(std::string_view path = "") const;

    /**
     * @brief Check if the Json described by the path is int64.
     *
     * Ensure that the path exists before calling this function.
     *
     *
     * @param path The path to the object, default value is root object ("").
     * @return true if Json is int64.
     * @return false if Json is not int64.
     *
     * @throws std::runtime_error If path is invalid or cannot be found.
     */
    bool isInt64(std::string_view path = "") const;

    /**
     * @brief Check if the Json described by the path is float.
     *
     * Ensure that the path exists before calling this function.
     *
     *
     * @param path The path to the object, default value is root object ("").
     * @return true if Json is float.
     * @return false if Json is not float.
     *
     * @throws std::runtime_error If path is invalid or cannot be found.
     */
    bool isFloat(std::string_view path = "") const;

    /**
     * @brief Check if the Json described by the path is double.
     *
     * Ensure that the path exists before calling this function.
     *
     *
     * @param path The path to the object, default value is root object ("").
     * @return true if Json is Double.
     * @return false if Json is not Double.
     *
     * @throws std::runtime_error If path is invalid or cannot be found.
     */
    bool isDouble(std::string_view path = "") const;

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
    bool isString(std::string_view path = "") const;

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
    bool isArray(std::string_view path = "") const;

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
    bool isObject(std::string_view path = "") const;

    /**
     * @brief Check if the Json described by the path is empty.
     *
     * Ensure that the path exists before calling this function.
     * If the Json is an array or object, check if it is empty.
     * If the Json is a string, check if it is empty.
     * If the Json is a number, check if it is 0.
     * If the Json is a boolean, check if it is false.
     * If the Json is null, return true.
     * @param path
     * @return true
     * @return false
     */
    bool isEmpty(std::string_view path = "") const;

    /**
     * @brief Get the type name of the Json.
     *
     * @return std::string The type name of the Json.
     */
    std::string typeName(std::string_view path = "") const;

    /**
     * @brief Get Type of the Json.
     *
     * @param path The path to the object, default value is root object ("").
     * @return Type The type of the Json.
     *
     * @throws std::runtime_error If:
     * - path is invalid or cannot be found.
     * - internal json type is not supported.
     */
    Type type(std::string_view path = "") const;

    /**
     * @brief Validate the Json agains the schema.
     *
     * @param schema The schema to validate against.
     * @return std::optional<base::Error> Error message if validation failed, std::nullopt
     * otherwise.
     */
    std::optional<base::Error> validate(const Json& schema) const;

    /**
     * @brief Check if the Json has duplicate keys.
     *
     * @return std::optional<base::Error> If the Json has duplicate keys, return the error
     */
    std::optional<base::Error> checkDuplicateKeys() const;

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
    void setNull(std::string_view path = "");

    /**
     * @brief Set the Boolean object at the path.
     * Parents objects are created if they do not exist.
     *
     * @param value The value to set.
     * @param path The path to the object, default value is root object ("").
     *
     * @throws std::runtime_error If path is invalid.
     */
    void setBool(bool value, std::string_view path = "");

    /**
     * @brief Set the Integer object at the path.
     * Parents objects are created if they do not exist.
     *
     * @param value The value to set.
     * @param path The path to the object, default value is root object ("").
     *
     * @throws std::runtime_error If path is invalid.
     */
    void setInt(int value, std::string_view path = "");

    /**
     * @brief Set the Integer object at the path.
     * Parents objects are created if they do not exist.
     *
     * @param value The value to set.
     * @param path The path to the object, default value is root object ("").
     *
     * @throws std::runtime_error If path is invalid.
     */
    void setInt64(int64_t value, std::string_view path = "");

    /**
     * @brief Set the Double object at the path.
     * Parents objects are created if they do not exist.
     *
     * @param value The value to set.
     * @param path The path to the object, default value is root object ("").
     *
     * @throws std::runtime_error If path is invalid.
     */
    void setDouble(double_t value, std::string_view path = "");

    /**
     * @brief Set the Double object at the path.
     * Parents objects are created if they do not exist.
     *
     * @param value The value to set.
     * @param path The path to the object, default value is root object ("").
     *
     * @throws std::runtime_error If path is invalid.
     */
    void setFloat(float_t value, std::string_view path = "");

    /**
     * @brief Set the String object at the path.
     * Parents objects are created if they do not exist.
     *
     * @param value The value to set.
     * @param path The path to the object, default value is root object ("").
     *
     * @throws std::runtime_error If path is invalid.
     */
    void setString(std::string_view value, std::string_view path = "");

    /**
     * @brief Set the Array object at the path.
     * Parents objects are created if they do not exist.
     *
     * @param path The path to the object, default value is root object ("").
     *
     * @throws std::runtime_error If path is invalid.
     */
    void setArray(std::string_view path = "");

    /**
     * @brief Set the Object object at the path.
     * Parents objects are created if they do not exist.
     *
     * @param path The path to the object, default value is root object ("").
     *
     * @throws std::runtime_error If path is invalid.
     */
    void setObject(std::string_view path = "");

    /**
     * @brief Append string to the Array object at the path.
     * Parents objects are created if they do not exist.
     * If the object is not an Array, it is converted to an Array.
     *
     * @param value The string to append.
     * @param path The path to the object, default value is root object ("").
     *
     * @throws std::runtime_error If path is invalid.
     */
    void appendString(std::string_view value, std::string_view path = "");

    /**
     * @brief Append Json to the Array object at the path.
     *
     * @param value The Json to append.
     * @param path The path to the object, default value is root object ("").
     *
     * @throws std::runtime_error If path is invalid.
     */
    void appendJson(const Json& value, std::string_view path = "");

    /**
     * @brief Erase Json object at the path.
     *
     * @param path The path to the object, default value is root object ("").
     * @return true if object was erased, false if object was not found.
     *
     * @throws std::runtime_error If path is invalid.
     */
    bool erase(std::string_view path = "");

    /**
     * @brief Merge the Json Value at the path with the given Json Value.
     *
     * Objects are merged, arrays are appended.
     * Merges only first level of the Json Value.
     *
     * @param other The Json Value to merge.
     * @param path  The path to the object, default value is root object ("").
     *
     * @throws std::runtime_error On the following conditions:
     * - If path is invalid.
     * - If either Json Values are not Object or Array.
     * - If Json Values are not the same type.
     */
    void merge(const bool isRecursive, const Json& other, std::string_view path = "");

    /**
     * @brief Merge the Json Value at the path with the given Json Value at reference
     * path.
     *
     * Merges only first level of the Json Value.
     * Reference value is deleted after merge.
     *
     * @param other The Json path pointing to the value to be merged.
     * @param path  The path to the object, default value is root object ("").
     *
     * @throws std::runtime_error On the following conditions:
     * - If either path are invalid.
     * - If either Json Values are not Object or Array.
     * - If Json Values are not the same type.
     */
    void merge(const bool isRecursive, std::string_view other, std::string_view path = "");

    /**
     * @brief Erases all the members of the JSON object that satisfy the given condition in the given Key (No the full
     * path)
     *
     * @param func A function that takes a string and returns a boolean indicating whether the member should be
     * erased. The string is the key of the member (No the full path)
     * @param recursive If true, the function will recursively erase members of nested objects.
     * @param path The path to the JSON object to modify.
     * @return true if any member was erased, false otherwise.
     *
     * @throws std::runtime_error if the given path is invalid.
     */
    bool eraseIfKey(const std::function<bool(const std::string&)>&, bool recursive = false, const std::string& = "");

    static Json makeObjectJson(const std::string& key, const json::Json& value);
};

} // namespace json

#endif // _JSON_H
