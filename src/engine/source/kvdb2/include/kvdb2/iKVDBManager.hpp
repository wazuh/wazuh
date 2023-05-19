#ifndef _IKVDBMANAGER_H
#define _IKVDBMANAGER_H

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <kvdb2/iKVDBScope.hpp>

namespace kvdbManager
{

using RefInfo = std::map<std::string, int>;

/**
 * @brief Interface for the KVDBManager class.
 *
 */
class IKVDBManager
{
public:
    virtual std::shared_ptr<IKVDBScope> getKVDBScope(const std::string& scopeName) = 0;

    virtual std::vector<std::string> listDBs(const bool loaded) = 0;
    virtual std::optional<base::Error> deleteDB(const std::string& name) = 0;
    virtual std::optional<base::Error> createDB(const std::string& name) = 0;
    virtual std::optional<base::Error> existsDB(const std::string& name) = 0;
    virtual std::map<std::string, RefInfo> getKVDBScopesInfo() = 0;
    virtual std::map<std::string, RefInfo> getKVDBHandlersInfo() = 0;
};

} // namespace kvdbManager

#endif // _IKVDBMANAGER_H
