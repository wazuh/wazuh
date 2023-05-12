#ifndef _IKVDBMANAGER_H
#define _IKVDBMANAGER_H

#include <memory>
#include <string>
#include <vector>

#include <kvdb2/iKVDBScope.hpp>

#include <optional>

namespace kvdbManager
{

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
};

} // namespace kvdbManager

#endif // _IKVDBMANAGER_H
