#ifndef _CMD_APICLNT_CONNECTION_HPP
#define _CMD_APICLNT_CONNECTION_HPP

#include <cstring>
#include <string>
#include <vector>

namespace cmd::apiclnt
{

enum class Method
{
    GET,
    POST,
    PUT,
    DELETE,
    ERROR_METHOD
};

constexpr auto methodToString(Method method)
{
    switch (method)
    {
        case Method::GET: return "GET";
        case Method::POST: return "POST";
        case Method::PUT: return "PUT";
        case Method::DELETE: return "DELETE";
        default: return "ERROR_METHOD";
    }
}

constexpr auto stringToMethod(const char* method)
{
    if (strcmp(method, "GET") == 0)
    {
        return Method::GET;
    }
    else if (strcmp(method, "POST") == 0)
    {
        return Method::POST;
    }
    else if (strcmp(method, "PUT") == 0)
    {
        return Method::PUT;
    }
    else if (strcmp(method, "DELETE") == 0)
    {
        return Method::DELETE;
    }
    else
    {
        return Method::ERROR_METHOD;
    }
}

struct Uri
{
    std::vector<std::string> parts;
    size_t size() const { return parts.size(); }
    Uri() = default;
    Uri(const Uri& other) { parts = other.parts; }
    Uri operator=(const Uri& other)
    {
        parts = other.parts;
        return *this;
    }
    Uri(Uri&& other) { parts = std::move(other.parts); }
    Uri operator=(Uri&& other)
    {
        parts = std::move(other.parts);
        return *this;
    }
    Uri(const std::string& uri)
    {
        std::string::size_type start {0};
        std::string::size_type end {0};
        while ((end = uri.find('/', start)) != std::string::npos)
        {
            parts.push_back(uri.substr(start, end - start));
            start = end + 1;
        }
        parts.push_back(uri.substr(start));
    }
    std::string operator[](size_t index) const { return parts[index]; }
    std::string operator[](size_t index) { return parts[index]; }
};

std::string connection(const std::string& socketPath, const std::string& request);
} // namespace cmd::apiclnt

#endif // _CMD_APICLNT_CONNECTION_HPP
