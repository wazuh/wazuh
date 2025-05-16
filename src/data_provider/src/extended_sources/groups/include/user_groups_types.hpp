#pragma once

#include <unistd.h>
#include <sys/types.h>

#ifdef __APPLE__
    using gid_type = int;
    using uid_type = int;
#else
    using gid_type = gid_t;
    using uid_type = uid_t;
#endif
