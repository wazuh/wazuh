#ifndef _PROTO_EMESSAGE_EMESSAGE_HPP
#define _PROTO_EMESSAGE_EMESSAGE_HPP

#include <type_traits>
#include <variant>

#include <base/error.hpp>
#include <base/json.hpp>
#include <google/protobuf/message.h>
#include <google/protobuf/struct.pb.h>
#include <google/protobuf/stubs/common.h>
#include <google/protobuf/util/json_util.h>

namespace eMessage
{
namespace detail
{
inline rapidjson::Value toRapidValue(const google::protobuf::Value& v, rapidjson::Document::AllocatorType& alloc);

inline rapidjson::Value toRapidObject(const google::protobuf::Struct& s, rapidjson::Document::AllocatorType& alloc)
{
    rapidjson::Value obj(rapidjson::kObjectType);

    for (const auto& [k, vv] : s.fields())
    {
        rapidjson::Value key(k.c_str(), static_cast<rapidjson::SizeType>(k.size()), alloc);
        obj.AddMember(key, toRapidValue(vv, alloc), alloc);
    }

    return obj;
}

inline rapidjson::Value toRapidArray(const google::protobuf::ListValue& l, rapidjson::Document::AllocatorType& alloc)
{
    rapidjson::Value arr(rapidjson::kArrayType);
    for (const auto& item : l.values())
    {
        arr.PushBack(toRapidValue(item, alloc), alloc);
    }
    return arr;
}

inline rapidjson::Value toRapidValue(const google::protobuf::Value& v, rapidjson::Document::AllocatorType& alloc)
{
    rapidjson::Value out;

    switch (v.kind_case())
    {
        case google::protobuf::Value::kNullValue: out.SetNull(); break;

        case google::protobuf::Value::kNumberValue: out.SetDouble(v.number_value()); break;

        case google::protobuf::Value::kStringValue:
        {
            const auto& s = v.string_value();
            out.SetString(s.c_str(), static_cast<rapidjson::SizeType>(s.size()), alloc);
            break;
        }

        case google::protobuf::Value::kBoolValue: out.SetBool(v.bool_value()); break;

        case google::protobuf::Value::kStructValue: out = toRapidObject(v.struct_value(), alloc); break;

        case google::protobuf::Value::kListValue: out = toRapidArray(v.list_value(), alloc); break;

        case google::protobuf::Value::KIND_NOT_SET:
        default: out.SetNull(); break;
    }

    return out;
}
} // namespace detail

/**
* @brief Parse a JSON string into a google::protobuf::Message.
 *
* @tparam T The type of the google::protobuf::Message.
* @param json The JSON string to parse.
* @return A variant object with either an error message or the parsed message.
*/
template<typename T>
std::variant<base::Error, T> eMessageFromJson(const std::string& json)
{
    static_assert(std::is_base_of<google::protobuf::Message, T>::value, "T must be a derived class of proto::Message");
    T message;

    google::protobuf::util::JsonParseOptions inOptions = google::protobuf::util::JsonParseOptions();
    // inOptions.ignore_unknown_fields = false;
    inOptions.ignore_unknown_fields = true;
    inOptions.case_insensitive_enum_parsing = false;

    const auto res = google::protobuf::util::JsonStringToMessage(json, &message, inOptions);
    if (res.ok())
    {
        return message;
    }
    return base::Error {res.ToString()};
}

/**
* @brief Serialize a google::protobuf::Message into a JSON string.
*
* @tparam T The type of the google::protobuf::Message.
* @param message The message to serialize.
* @param printPrimitiveFields Whether to always print primitive fields, even if their values are their default values.
* @return A variant object with either an error message or the JSON string.
*/
template<typename T>
std::variant<base::Error, std::string> eMessageToJson(const T& message, bool printPrimitiveFields = true)
{
    static_assert(std::is_base_of<google::protobuf::Message, T>::value, "T must be a derived class of proto::Message");
    std::string dataStr;

    google::protobuf::util::JsonPrintOptions outOptions = google::protobuf::util::JsonPrintOptions();
    outOptions.add_whitespace = false;
    outOptions.always_print_primitive_fields = printPrimitiveFields;
    outOptions.preserve_proto_field_names = true;
    outOptions.always_print_enums_as_ints = false;

    const auto res = google::protobuf::util::MessageToJsonString(message, &dataStr, outOptions);
    if (res.ok())
    {
        return dataStr;
    }
    return base::Error {res.ToString()};
}

/**
* @brief Serialize a google::protobuf::RepeatedPtrField<T> into a JSON string.
*
* @tparam T The type of the elements in the google::protobuf::RepeatedPtrField.
* @param repeatedPtrField The field to serialize.
* @param printPrimitiveFields Whether to always print primitive fields, even if their values are their default values.
* @return A variant object with either an error message or the JSON string.
*/
template<typename T>
std::variant<base::Error, std::string>
eRepeatedFieldToJson(const google::protobuf::RepeatedPtrField<T>& repeatedPtrField, bool printPrimitiveFields = true)
{
    static_assert(std::is_base_of<google::protobuf::Message, T>::value, "T must be a derived class of proto::Message");

    google::protobuf::util::JsonPrintOptions outOptions = google::protobuf::util::JsonPrintOptions();
    outOptions.add_whitespace = false;
    outOptions.always_print_primitive_fields = printPrimitiveFields;
    outOptions.preserve_proto_field_names = true;
    outOptions.always_print_enums_as_ints = false;

    std::string jsonArray = "[";

    for (const auto& message : repeatedPtrField)
    {
        std::string dataStr;
        const auto res = google::protobuf::util::MessageToJsonString(message, &dataStr, outOptions);
        if (!res.ok())
        {
            return base::Error {res.ToString()};
        }
        jsonArray += dataStr + ",";
    }

    if (jsonArray.back() == ',')
    {
        jsonArray.pop_back();
    }
    jsonArray += "]";
    return jsonArray;
}

/**
 * @brief Shutdown the eMessage library (call this before the program exits)
 *
 * This function shutdown the google::protobuf library, is not necessary to call but is recommended for a clean exit.
 */
inline void ShutdownEMessageLibrary()
{
    google::protobuf::ShutdownProtobufLibrary();
}

/**
 * @brief Convert a google::protobuf::Struct into a json::Json object.
 *
 * @param s The Struct to convert.
 * @return A variant object with either an error message or the json::Json object.
 */
inline std::variant<base::Error, json::Json> eStructToJson(const google::protobuf::Struct& s)
{
    try
    {
        rapidjson::Document doc;
        doc.SetObject();
        auto& alloc = doc.GetAllocator();

        for (const auto& [k, vv] : s.fields())
        {
            rapidjson::Value key(k.c_str(), static_cast<rapidjson::SizeType>(k.size()), alloc);
            doc.AddMember(key, detail::toRapidValue(vv, alloc), alloc);
        }

        return json::Json {std::move(doc)};
    }
    catch (const std::exception& e)
    {
        return base::Error {e.what()};
    }
}

} // namespace eMessage

#endif // _PROTO_EMESSAGE_EMESSAGE_HPP
