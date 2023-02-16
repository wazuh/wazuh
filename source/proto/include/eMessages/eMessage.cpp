#include "eMessage.h"


namespace
{
std::variant<base::Error, std::string> eMessageToJson(const google::protobuf::Message& message, bool pretty = false)
{
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


std::variant<base::Error, std::string> eMessageToJson(const google::protobuf::Message& message, bool pretty = false);

// Template for message

std::variant<base::Error, T> eMessageFromJson(const std::string& json)
{
    T message;
    google::protobuf::util::JsonParseOptions inOptions = google::protobuf::util::JsonParseOptions();
    inOptions.ignore_unknown_fields = false;

    const auto res = google::protobuf::util::JsonStringToMessage(json, &message);
    if (res.ok())
    {
        return message;
    }
    return base::Error {res.ToString()};
}

} // namespace
