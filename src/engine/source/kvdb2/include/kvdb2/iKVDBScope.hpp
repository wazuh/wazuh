#ifndef _IKVDBSCOPE_H
#define _IKVDBSCOPE_H

#include <memory>

#include <kvdb2/iKVDBHandler.hpp>

namespace kvdbManager
{

/**
 * @brief Interface for the KVDBScope class.
 *
 */
class IKVDBScope
{
public:
    virtual std::variant<std::unique_ptr<IKVDBHandler>, base::Error> getKVDBHandler(const std::string& dbName) = 0;
};

} // namespace kvdbManager

#endif // _IKVDBSCOPE_H
