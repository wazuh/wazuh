#ifndef _IKVDBHANDLER_H
#define _IKVDBHANDLER_H

#include <error.hpp>
#include <string>
#include <variant>

namespace kvdbManager
{

class IKVDBHandler
{
public:
    virtual std::variant<bool, base::Error> set(const std::string& key, const std::string& value) = 0;
    virtual std::variant<bool, base::Error> add(const std::string& key) = 0;
    virtual std::variant<bool, base::Error> remove(const std::string& key) = 0;
    virtual std::variant<bool, base::Error> contains(const std::string& key) = 0;
    virtual std::variant<std::string, base::Error> get(const std::string& key) = 0;
};

} // namespace kvdbManager

#endif // _IKVDBHANDLER_H
