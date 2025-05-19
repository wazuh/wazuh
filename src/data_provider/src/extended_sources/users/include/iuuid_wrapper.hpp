#pragma once

#include <uuid/uuid.h>

class IUUIDWrapper
{
    public:
        virtual ~IUUIDWrapper() = default;
        virtual void uidToUUID(uid_t uid, uuid_t& uuid) = 0;
        virtual void uuidToString(const uuid_t& uuid, uuid_string_t& str) = 0;
};
