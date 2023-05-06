#ifndef _IKVDBMANAGER_H
#define _IKVDBMANAGER_H

#include <memory>
#include <string>

#include <kvdb2/iKVDBScope.hpp>

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
};

} // namespace kvdbManager

#endif // _IKVDBMANAGER_H
