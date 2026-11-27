#include "image_source_files.hpp"

#include <gtest/gtest.h>

#include <string>

using wazuh::container_baseline::ImageSourceFiles;
using wazuh::container_baseline::ImageSourceKind;

TEST(ImageSourceFiles, TheRpmWriteAheadLogsAreListedAsWal)
{
    std::size_t count = 0;
    const auto* files = ImageSourceFiles(count);
    std::size_t wal = 0;

    for (std::size_t i = 0; i < count; ++i)
    {
        const std::string path {files[i].path};
        const bool isWal = path.size() > 4 && path.compare(path.size() - 4, 4, "-wal") == 0;
        EXPECT_EQ(isWal, files[i].kind == ImageSourceKind::wal) << path;
        wal += isWal ? 1 : 0;
    }

    EXPECT_EQ(wal, 2u);
}
