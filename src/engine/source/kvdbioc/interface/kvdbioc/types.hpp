#ifndef _KVDBIOC_TYPES_HPP
#define _KVDBIOC_TYPES_HPP

#include <string>
#include <vector>
#include <cstddef>

namespace kvdb
{
    using DbName = std::string;

    struct ImportResult
    {
        DbName      name;
        std::size_t importedRecords {0};
    };
} // namespace kvdb

#endif // _KVDBIOC_TYPES_HPP
