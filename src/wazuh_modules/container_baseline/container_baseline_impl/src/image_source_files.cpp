#include "image_source_files.hpp"

namespace wazuh::container_baseline {

namespace {

// Keep in sync with user_scanner.cpp, os_scanner.cpp and package_scanner.cpp.
constexpr ImageSourceFile kImageSourceFiles[] = {
    {"/etc/passwd", IMAGE_SOURCE_USERS, false},
    {"/etc/group", IMAGE_SOURCE_USERS, false},
    {"/etc/os-release", IMAGE_SOURCE_OS, false},
    {"/usr/lib/os-release", IMAGE_SOURCE_OS, false},
    {"/var/lib/dpkg/status", IMAGE_SOURCE_PACKAGES, false},
    // Distroless dpkg: one status-format file per package, read when status is absent.
    {"/var/lib/dpkg/status.d", IMAGE_SOURCE_PACKAGES, true},
    {"/lib/apk/db/installed", IMAGE_SOURCE_PACKAGES, false},
    {"/var/lib/rpm/rpmdb.sqlite", IMAGE_SOURCE_PACKAGES, false},
    {"/usr/lib/sysimage/rpm/rpmdb.sqlite", IMAGE_SOURCE_PACKAGES, false},
    {"/var/lib/rpm/Packages", IMAGE_SOURCE_PACKAGES, false},
    {"/usr/lib/sysimage/rpm/Packages", IMAGE_SOURCE_PACKAGES, false},
};

} // namespace

const ImageSourceFile* ImageSourceFiles(std::size_t& count)
{
    count = sizeof(kImageSourceFiles) / sizeof(kImageSourceFiles[0]);
    return kImageSourceFiles;
}

} // namespace wazuh::container_baseline
