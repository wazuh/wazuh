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
    virtual void setName(const std::string& name) = 0;
    virtual std::string getName() const = 0;
    virtual std::shared_ptr<IKVDBHandler> getKVDBHandler(const std::string& dbName) = 0;
};

} // namespace kvdbManager

#endif // _IKVDBSCOPE_H
