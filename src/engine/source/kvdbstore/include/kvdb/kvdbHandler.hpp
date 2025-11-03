#ifndef _KVDB_HANDLER_H
#define _KVDB_HANDLER_H

#include <kvdb/ikvdbhandler.hpp>

namespace kvdbStore
{

class KVDBHandler final : public IKVDBHandler
{
public:
    KVDBHandler() = default;
    ~KVDBHandler() = default;
};

} // namespace kvdbStore

#endif // _KVDB_HANDLER_H
