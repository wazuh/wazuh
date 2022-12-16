#ifndef _CMD_APICLNT_CATALOG_HPP
#define _CMD_APICLNT_CATALOG_HPP

#include <cstring>
#include <string>
#include <vector>

namespace cmd
{

namespace catalog_details
{
enum class Action
{
    LIST,
    GET,
    UPDATE,
    CREATE,
    DELETE,
    VALIDATE,
    LOAD,
    ERROR_ACTION
};

constexpr auto actionToString(Action action)
{
    switch (action)
    {
        case Action::LIST: return "list";
        case Action::GET: return "get";
        case Action::UPDATE: return "update";
        case Action::CREATE: return "create";
        case Action::DELETE: return "delete";
        case Action::VALIDATE: return "validate";
        case Action::LOAD: return "load";
        default: return "ERROR_ACTION";
    }
}

constexpr auto stringToAction(const char* action)
{
    if (strcmp(action, actionToString(Action::LIST)) == 0)
    {
        return Action::LIST;
    }
    else if (strcmp(action, actionToString(Action::GET)) == 0)
    {
        return Action::GET;
    }
    else if (strcmp(action, actionToString(Action::UPDATE)) == 0)
    {
        return Action::UPDATE;
    }
    else if (strcmp(action, actionToString(Action::CREATE)) == 0)
    {
        return Action::CREATE;
    }
    else if (strcmp(action, actionToString(Action::DELETE)) == 0)
    {
        return Action::DELETE;
    }
    else if (strcmp(action, actionToString(Action::VALIDATE)) == 0)
    {
        return Action::VALIDATE;
    }
    else if (strcmp(action, actionToString(Action::LOAD)) == 0)
    {
        return Action::LOAD;
    }
    else
    {
        return Action::ERROR_ACTION;
    }
}

void singleRequest(const std::string& socketPath,
                   const std::string& actionStr,
                   const std::string& nameStr,
                   const std::string& format,
                   const std::string& content,
                   const std::string& path);

void loadRuleset(const std::string& socketPath,
                    const std::string& name,
                    const std::string& collectionPath,
                    const std::string& format,
                    const bool recursive);

} // namespace catalog_details

/**
 * @brief Operate the engine catalog through the API
 *
 * @param socketPath Path to the api socket where the engine is listening
 * @param actionStr Action to use: list, get, update, create, delete
 * @param nameStr Name of the item to operate on
 * @param format Format of the content: json, yaml
 * @param content  Content of the request, depending on the action
 * @param recursive Option to recursively traverse or not a directory
 */
void catalog(const std::string& socketPath,
             const std::string& actionStr,
             const std::string& nameStr,
             const std::string& format,
             const std::string& content,
             const std::string& path,
             bool recursive,
             int logLevel);
} // namespace cmd

#endif // _CMD_APICLNT_CATALOG_HPP
