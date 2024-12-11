#ifndef FIELD_ALERT_HELPER_HPP
#define FIELD_ALERT_HELPER_HPP

#include <base/json.hpp>
#include <string>
#include <type_traits>

namespace FieldAlertHelper
{

/**
 * @brief High-performance utility function to replace empty strings or zero/negative numeric values with
 * placeholders.
 *
 * This function ensures fields such as strings and numeric values are not left empty or with undesired values.
 * It either returns the original value or a default placeholder based on the input type and its value:
 *
 * - For `std::string` types, it returns `"-"` if the string is empty, otherwise it returns the original string.
 * - For numeric types (`double`, `int`, etc.), it returns `-1` if the value is zero or negative, otherwise it
 * returns the original value.
 *
 * The function is optimized for performance with minimal branching and efficient memory management.
 *
 * @tparam T The type of the field being processed (`std::string`, `double`, `int`, etc.).
 * @param field The field value to check and potentially replace.
 * @return nlohmann::json A JSON-compatible value, either the original value or a placeholder.
 *
 * @throws std::runtime_error If the field type is unsupported.
 */
template<typename T>
nlohmann::json fillEmptyOrNegative(T&& field)
{
    if constexpr (std::is_same_v<std::remove_cv_t<std::remove_reference_t<T>>,
                                 std::string_view> || std::is_same_v<T, std::string>)
    {
        // Return "-" if the string is empty, otherwise return the original string
        return field.empty() ? "-" : std::forward<T>(field);
    }
    else if constexpr (std::is_arithmetic_v<std::remove_cv_t<std::remove_reference_t<T>>>)
    {
        // Use a small epsilon value for floating-point comparisons
        constexpr double epsilon = 1e-9;

        // Handle floating-point numbers
        if constexpr (std::is_floating_point_v<std::remove_cv_t<std::remove_reference_t<T>>>)
        {
            return (std::abs(field) < epsilon) ? -1.0 : std::forward<T>(field);
        }
        else
        {
            // Handle integral numbers: return -1 for negatives
            return (field < 0) ? -1 : std::forward<T>(field);
        }
    }
    else
    {
        // Compile-time check to ensure unsupported types are caught early
        static_assert(std::is_arithmetic_v<std::remove_cv_t<std::remove_reference_t<
                              T>>> || std::is_same_v<std::remove_cv_t<std::remove_reference_t<T>>, std::string>,
                      "Unsupported type for fillEmptyOrNegative");
    }
}

} // namespace FieldAlertHelper

#endif // FIELD_ALERT_HELPER_HPP
