#include "image_source_files.hpp"

namespace wazuh::container_baseline {

namespace {

// Keep in sync with user_scanner.cpp, os_scanner.cpp and package_scanner.cpp.
constexpr ImageSourceFile kImageSourceFiles[] = {
    {"/etc/passwd", IMAGE_SOURCE_USERS, ImageSourceKind::file},
    {"/etc/group", IMAGE_SOURCE_USERS, ImageSourceKind::file},
    {"/etc/os-release", IMAGE_SOURCE_OS, ImageSourceKind::file},
    {"/usr/lib/os-release", IMAGE_SOURCE_OS, ImageSourceKind::file},
    {"/var/lib/dpkg/status", IMAGE_SOURCE_PACKAGES, ImageSourceKind::file},
    // Distroless dpkg: one status-format file per package, read when status is absent.
    {"/var/lib/dpkg/status.d", IMAGE_SOURCE_PACKAGES, ImageSourceKind::directory},
    {"/lib/apk/db/installed", IMAGE_SOURCE_PACKAGES, ImageSourceKind::file},
    {"/var/lib/rpm/rpmdb.sqlite", IMAGE_SOURCE_PACKAGES, ImageSourceKind::file},
    {"/usr/lib/sysimage/rpm/rpmdb.sqlite", IMAGE_SOURCE_PACKAGES, ImageSourceKind::file},
    {"/var/lib/rpm/Packages", IMAGE_SOURCE_PACKAGES, ImageSourceKind::file},
    {"/usr/lib/sysimage/rpm/Packages", IMAGE_SOURCE_PACKAGES, ImageSourceKind::file},
    // The package scanner applies a non-empty WAL to its copy of the database.
    {"/var/lib/rpm/rpmdb.sqlite-wal", IMAGE_SOURCE_PACKAGES, ImageSourceKind::wal},
    {"/usr/lib/sysimage/rpm/rpmdb.sqlite-wal", IMAGE_SOURCE_PACKAGES, ImageSourceKind::wal},
};

} // namespace

const ImageSourceFile* ImageSourceFiles(std::size_t& count)
{
    count = sizeof(kImageSourceFiles) / sizeof(kImageSourceFiles[0]);
    return kImageSourceFiles;
}

} // namespace wazuh::container_baseline
