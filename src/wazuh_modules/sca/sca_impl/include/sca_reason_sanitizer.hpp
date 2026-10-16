#pragma once

#include <cstddef>
#include <string>

namespace sca
{
    /// @brief Largest reason kept on a check, in bytes. Below ignore_above on check.reason in the
    ///        index template, so a stored reason stays searchable.
    constexpr size_t REASON_MAX_LENGTH {1024};

    /// @brief Makes a check's reason safe to store and publish.
    /// @details Bytes that are not valid UTF-8 become '?'. A reason over maxLength is cut at its last
    ///          whole line that fits and ends with a "[truncated]" line, both within maxLength.
    /// @param reason The raw reason, one item per line.
    /// @param maxLength Largest result in bytes.
    /// @return A valid UTF-8 reason of at most maxLength bytes.
    std::string SanitizeReason(const std::string& reason, size_t maxLength);
} // namespace sca
