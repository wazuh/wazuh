#ifndef __DISKSTORAGE_TEST_H__
#define __DISKSTORAGE_TEST_H__

#include <gtest/gtest.h>
#include <fstream>
#include "catalog/storageDriver/disk/DiskStorage.hpp"

char* createDBtmp()
{


    auto template_BaseDir = std::filesystem::temp_directory_path();
    template_BaseDir /= "wazuh_catalog_disk_test_XXXXXXXXX";
    char* tmpDir = strdup(template_BaseDir.string().c_str());

    // Create base struct of tmp db from template
    if (mkdtemp(tmpDir) == nullptr)
    {
        throw std::runtime_error("Failed to create temporary directory");
    }

    std::filesystem::path tmpDirPath {tmpDir};

    if (!(std::filesystem::create_directory(tmpDirPath / "decoders") &&
            std::filesystem::create_directory(tmpDirPath / "rules") &&
            std::filesystem::create_directory(tmpDirPath / "output") &&
            std::filesystem::create_directory(tmpDirPath / "filters")))
    {
        throw std::runtime_error("Failed to create temporary directory");
    }


    return tmpDir;
}

void removeDBtmp(char** tmpDir)
{

    std::filesystem::remove_all(*tmpDir);
    free(*tmpDir);
    *tmpDir = nullptr;
}

#endif // __DISKSTORAGE_TEST_H__
