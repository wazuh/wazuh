#pragma once

#include <uuid/uuid.h>
#include <membership.h>

#include "iuuid_wrapper.hpp"

class UUIDWrapper : public IUUIDWrapper
{
    public:
        void uidToUUID(uid_t uid, uuid_t& uuid) override
        {
            mbr_uid_to_uuid(uid, uuid);
        }

        void uuidToString(const uuid_t& uuid, uuid_string_t& str) override
        {
            uuid_unparse(uuid, str);
        }
};
