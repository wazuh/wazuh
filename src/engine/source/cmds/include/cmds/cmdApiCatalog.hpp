#ifndef _CMD_APICLNT_CATALOG_HPP
#define _CMD_APICLNT_CATALOG_HPP

#include <cstring>
#include <string>
#include <vector>

namespace cmd
{

namespace catalog_details
{
enum class Method
{
    LIST,
    GET,
    UPDATE,
    CREATE,
    DELETE,
    VALIDATE,
    ERROR_METHOD
};

constexpr auto methodToString(Method method)
{
    switch (method)
    {
        case Method::LIST: return "list";
        case Method::GET: return "get";
        case Method::UPDATE: return "update";
        case Method::CREATE: return "create";
        case Method::DELETE: return "delete";
        case Method::VALIDATE: return "validate";
        default: return "ERROR_METHOD";
    }
}

constexpr auto stringToMethod(const char* method)
{
    if (strcmp(method, methodToString(Method::LIST)) == 0)
    {
        return Method::LIST;
    }
    else if (strcmp(method, methodToString(Method::GET)) == 0)
    {
        return Method::GET;
    }
    else if (strcmp(method, methodToString(Method::UPDATE)) == 0)
    {
        return Method::UPDATE;
    }
    else if (strcmp(method, methodToString(Method::CREATE)) == 0)
    {
        return Method::CREATE;
    }
    else if (strcmp(method, methodToString(Method::DELETE)) == 0)
    {
        return Method::DELETE;
    }
    else if (strcmp(method, methodToString(Method::VALIDATE)) == 0)
    {
        return Method::VALIDATE;
    }
    else
    {
        return Method::ERROR_METHOD;
    }
}

} // namespace catalog_details

/**
 * @brief Operate the engine catalog through the API
 *
 * @param socketPath Path to the api socket where the engine is listening
 * @param methodStr Method to use: list, get, update, create, delete
 * @param nameStr Name of the item to operate on
 * @param format Format of the content: json, yaml
 * @param content  Content of the request, depending on the method
 */
void catalog(const std::string& socketPath,
             const std::string& methodStr,
             const std::string& nameStr,
             const std::string& format,
             const std::string& content);
} // namespace cmd

#endif // _CMD_APICLNT_CATALOG_HPP
