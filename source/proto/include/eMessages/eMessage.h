#ifndef _PROTO_EMESSAGE_EMESSAGE_HPP
#define _PROTO_EMESSAGE_EMESSAGE_HPP

#include <variant>
#include <type_traits>

#include <error.hpp>
#include <google/protobuf/message.h>
#include <google/protobuf/util/json_util.h>

namespace eMessage
{

template <typename T>
std::variant<base::Error, T> eMessageFromJson(const std::string& json)
{
    static_assert(std::is_base_of<google::protobuf::Message, T>::value, "T must be a derived class of proto::Message");
    T message;

    google::protobuf::util::JsonParseOptions inOptions = google::protobuf::util::JsonParseOptions();
    //inOptions.ignore_unknown_fields = false;
    inOptions.ignore_unknown_fields = true;
    inOptions.case_insensitive_enum_parsing = false;

    const auto res = google::protobuf::util::JsonStringToMessage(json, &message, inOptions);
    if (res.ok())
    {
        return message;
    }
    return base::Error {res.ToString()};
}

template <typename T>
std::variant<base::Error, std::string> eMessageToJson(const T& message, bool pretty = false)
{
    static_assert(std::is_base_of<google::protobuf::Message, T>::value, "T must be a derived class of proto::Message");
    std::string dataStr;

    google::protobuf::util::JsonPrintOptions outOptions = google::protobuf::util::JsonPrintOptions();
    outOptions.add_whitespace = pretty;
    outOptions.always_print_primitive_fields = true;
    outOptions.preserve_proto_field_names = true;

    const auto res = google::protobuf::util::MessageToJsonString(message, &dataStr, outOptions);
    if (res.ok())
    {
        return dataStr;
    }
    return base::Error {res.ToString()};

}

} // namespace eMessage

#endif // _PROTO_EMESSAGE_EMESSAGE_HPP
