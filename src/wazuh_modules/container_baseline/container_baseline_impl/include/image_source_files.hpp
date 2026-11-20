#pragma once

#include <cstddef>

namespace wazuh::container_baseline {

/// @brief Data classes an image source file feeds.
inline constexpr unsigned IMAGE_SOURCE_PACKAGES = 1u << 0;
inline constexpr unsigned IMAGE_SOURCE_USERS    = 1u << 1;
inline constexpr unsigned IMAGE_SOURCE_OS       = 1u << 2;

/// @brief A file, inside the container's rootfs, that packages, users, groups
/// or the OS record are read from.
struct ImageSourceFile
{
    const char* path;      ///< Absolute in-container path.
    unsigned    classes;   ///< IMAGE_SOURCE_* bits.
    bool        directory; ///< The files directly inside it are the sources.
};

/// @brief Every file the user, OS and package scanners read. The image-content
/// cache fingerprints exactly these, so a path read but missing here would let
/// a modified file serve stale cached rows.
[[nodiscard]] const ImageSourceFile* ImageSourceFiles(std::size_t& count);

} // namespace wazuh::container_baseline
