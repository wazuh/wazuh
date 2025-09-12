/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * December 16, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REFLECTIVE_JSON_HPP
#define _REFLECTIVE_JSON_HPP

#include <array>
#include <charconv>
#include <functional>
#include <iostream>
#include <list>
#include <map>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <vector>

constexpr auto DEFAULT_INT_VALUE = INT64_MIN;
constexpr auto DEFAULT_INT32_VALUE = INT32_MIN;
constexpr auto DEFAULT_DOUBLE_VALUE = 0.0;
constexpr auto CHAR_SIZE {256};
constexpr auto BUFFER_SIZE {32};

#define REFLECTABLE(...)                                                                                               \
    static constexpr auto fields()                                                                                     \
    {                                                                                                                  \
        return std::make_tuple(__VA_ARGS__);                                                                           \
    }

static std::array<const char*, CHAR_SIZE> ESCAPE_TABLE = []
{
    std::array<const char*, CHAR_SIZE> table {};
    for (int i = 0; i < CHAR_SIZE; ++i)
    {
        table[i] = nullptr;
    }

    table['"'] = R"(\")";
    table['\\'] = R"(\\)";
    table['\b'] = "\\b";
    table['\f'] = "\\f";
    table['\n'] = "\\n";
    table['\r'] = "\\r";
    table['\t'] = "\\t";

    for (int i = 0; i < 0x20; ++i)
    {
        if (!table[i])
        {
            static char buffer[CHAR_SIZE][7];
            snprintf(buffer[i], 7, "\\u%04x", i);
            table[i] = buffer[i];
        }
    }
    return table;
}();

inline bool needEscape(std::string_view input)
{
    // Kept the unsigned char to avoid errors with unicode characters
    for (unsigned char chr : input)
    {
        if (ESCAPE_TABLE[chr])
        {
            return true;
        }
    }
    return false;
}
inline void escapeJSONString(std::string_view input, std::string& output)
{
    // Kept the unsigned char to avoid errors with unicode characters
    for (unsigned char chr : input)
    {
        if (ESCAPE_TABLE[chr])
        {
            output.append(ESCAPE_TABLE[chr]);
        }
        else
        {
            output.push_back(chr);
        }
    }
}

template<typename T>
struct IsMap : std::false_type
{
};

template<typename K, typename V, typename... Args>
struct IsMap<std::map<K, V, Args...>> : std::true_type
{
};

template<typename K, typename V, typename... Args>
struct IsMap<std::unordered_map<K, V, Args...>> : std::true_type
{
};

template<typename T>
constexpr bool IS_MAP_V = IsMap<std::decay_t<T>>::value;

template<typename T>
struct IsVector : std::false_type
{
};

template<typename T, typename... Args>
struct IsVector<std::vector<T, Args...>> : std::true_type
{
};

template<typename T>
constexpr bool IS_VECTOR_V = IsVector<std::decay_t<T>>::value;

template<typename T>
struct IsList : std::false_type
{
};

template<typename T, typename... Args>
struct IsList<std::list<T, Args...>> : std::true_type
{
};

template<typename T>
constexpr bool IS_LIST_V = IsList<std::decay_t<T>>::value;

template<typename T, typename = void>
struct IsReflectable : std::false_type
{
};

template<typename T>
struct IsReflectable<T, std::void_t<decltype(T::fields())>> : std::true_type
{
};

template<typename T>
constexpr bool IS_REFLECTABLE_MEMBER =
    std::is_same_v<std::decay_t<T>, std::string_view> || std::is_same_v<std::decay_t<T>, std::string> ||
    std::is_same_v<std::decay_t<T>, std::pmr::string> || std::is_same_v<std::decay_t<T>, double> ||
    std::is_same_v<std::decay_t<T>, bool> || IsMap<std::decay_t<T>>::value || IsVector<std::decay_t<T>>::value ||
    IsList<std::decay_t<T>>::value || IsReflectable<std::decay_t<T>>::value ||
    std::is_same_v<std::decay_t<T>, std::int64_t> || std::is_same_v<std::decay_t<T>, std::int32_t>;

template<typename C, typename T>
constexpr auto makeFieldChecked(const char* keyLiteral, const char* keyLiteralField, T C::* member)
{
    static_assert(IS_REFLECTABLE_MEMBER<T>, "Invalid member type for reflection");
    return std::make_tuple(std::string_view {keyLiteral}, std::string_view {keyLiteralField}, member);
}

#define MAKE_FIELD(keyLiteral, memberPtr) makeFieldChecked(keyLiteral, "\"" keyLiteral "\":", memberPtr)

template<typename T>
std::enable_if_t<std::is_same_v<int32_t, T>, bool> isEmpty(T value)
{
    return value == DEFAULT_INT32_VALUE;
}

template<typename T>
std::enable_if_t<std::is_same_v<int64_t, T>, bool> isEmpty(T value)
{
    return value == DEFAULT_INT_VALUE;
}

template<typename T>
std::enable_if_t<std::is_same_v<double, T>, bool> isEmpty(T value)
{
    return value == DEFAULT_DOUBLE_VALUE;
}

inline bool isEmpty([[maybe_unused]] bool value)
{
    return false;
}

inline bool isEmpty(std::string_view value)
{
    return value.empty();
}

inline bool isEmpty(const std::string& value)
{
    return value.empty();
}

template<typename K, typename V>
bool isEmpty(const std::unordered_map<K, V>& map)
{
    return map.empty();
}

template<typename K, typename V>
bool isEmpty(const std::map<K, V>& map)
{
    return map.empty();
}

template<typename K, typename V>
bool isEmpty(const std::map<K, V, std::less<>>& map)
{
    return map.empty();
}

template<typename V>
bool isEmpty(const std::vector<V>& vector)
{
    return vector.empty();
}

template<typename V>
bool isEmpty(const std::list<V>& list)
{
    return list.empty();
}

template<typename V>
bool isEmpty(const std::pmr::vector<V>& vector)
{
    return vector.empty();
}

template<typename T>
std::enable_if_t<IsReflectable<T>::value, bool> isEmpty(const T& obj)
{
    constexpr auto fields = T::fields();
    bool allEmpty = true;
    std::apply([&](auto&&... field) { ((allEmpty = allEmpty && isEmpty(obj.*(std::get<2>(field)))), ...); }, fields);
    return allEmpty;
}

template<typename T>
bool isSingleSpace(const T& obj)
{
    if constexpr (IsReflectable<T>::value)
    {
        constexpr auto fields = T::fields();
        bool allSpaces = true;
        std::apply(
            [&](auto&&... field) {
                ((allSpaces = allSpaces && isSingleSpace(obj.*(std::get<2>(field)))), ...);
            },
            fields
    );
        return allSpaces;
    }
    else if constexpr (std::is_same_v<std::decay_t<T>, std::string> ||
                       std::is_same_v<std::decay_t<T>, std::string_view>)
    {
        return obj.size() == 1 && obj[0] == ' ';
    }
    else
    {
        return false;
    }
}

template<typename K, typename V>
std::string jsonFieldToString(const std::unordered_map<K, V>& map)
{
    std::string json = "{";
    size_t count = 0;
    char buffer[BUFFER_SIZE] = {};
    for (const auto& [key, value] : map)
    {
        if (count++ > 0)
        {
            json.push_back(',');
        }
        json.push_back('\"');
        json.append(key);
        json.push_back('\"');
        json.push_back(':');
        if constexpr (std::is_same_v<std::string, std::decay_t<decltype(value)>> ||
                      std::is_same_v<std::string_view, std::decay_t<decltype(value)>>)
        {
            json.push_back('\"');
            if (needEscape(value))
            {
                escapeJSONString(value, json);
            }
            else
            {
                json.append(value);
            }
            json.push_back('\"');
        }
        else if constexpr (std::is_arithmetic_v<std::decay_t<decltype(value)>> ||
                           std::is_same_v<double, std::decay_t<decltype(value)>> ||
                           std::is_same_v<bool, std::decay_t<decltype(value)>>)
        {
            auto [ptr, ec] = std::to_chars(buffer, buffer + sizeof(buffer), value);
            if (ec == std::errc())
            {
                json.append(buffer);
            }
            else
            {
                json.append("0");
            }
            std::fill(buffer, buffer + sizeof(buffer), '\0');
        }
        else
        {
            json.append(jsonFieldToString(value));
        }
    }
    json.push_back('}');
    return json;
}

template<typename T, bool NOEMPTY, bool NOSINGLESPACE>
std::string jsonFieldToString(const T& obj);
template<typename T, bool NOEMPTY, bool NOSINGLESPACE>
void jsonFieldToString(const T& obj, std::string& json);

template<typename T, bool NOEMPTY = true, bool NOSINGLESPACE = true>
std::enable_if_t<IsReflectable<T>::value, void> serializeToJSON(const T& obj, std::string& json)
{
    json.push_back('{');
    constexpr auto fields = T::fields();
    char buffer[BUFFER_SIZE] = {};

    size_t count = 0;
    std::apply(
        [&](auto&&... field)
        {
            ((
                 [&]
                 {
                     const auto& data = obj.*(std::get<2>(field));

                     if constexpr (NOEMPTY)
                     {
                         if (isEmpty(data))
                         {
                             return;
                         }
                     }

                     if constexpr (NOSINGLESPACE)
                     {
                         if (isSingleSpace(data))
                         {
                             return;
                         }
                     }

                     if (count++ > 0)
                     {
                         json.push_back(',');
                     }
                     json.append(std::get<1>(field));
                     //  If is string add quotes
                     if constexpr (std::is_same_v<std::string, std::decay_t<decltype(data)>> ||
                                   std::is_same_v<std::string_view, std::decay_t<decltype(data)>>)
                     {

                         json.push_back('"');
                         if (needEscape(data))
                         {
                             escapeJSONString(data, json);
                         }
                         else
                         {
                             json.append(data);
                         }
                         json.push_back('"');
                     }
                     else if constexpr (std::is_same_v<double, std::decay_t<decltype(data)>>)
                     {
                         // Special case: GCC 9.4 doesn't support std::to_chars(double), so we use snprintf
                         int len = std::snprintf(buffer, sizeof(buffer), "%g", data);
                         if (len > 0 && len < static_cast<int>(sizeof(buffer)))
                         {
                             json.append(buffer);
                         }
                         else
                         {
                             json.append("0");
                         }
                         std::fill(buffer, buffer + sizeof(buffer), '\0');
                     }
                     else if constexpr (std::is_arithmetic_v<std::decay_t<decltype(data)>> &&
                                        !std::is_same_v<bool, std::decay_t<decltype(data)>>)
                     {
                         // Use to_chars for ints/floats where supported
                         auto [ptr, ec] = std::to_chars(buffer, buffer + sizeof(buffer), data);
                         if (ec == std::errc())
                         {
                             json.append(buffer, ptr);
                         }
                         else
                         {
                             json.append("0");
                         }
                         std::fill(buffer, buffer + sizeof(buffer), '\0');
                     }
                     else if constexpr (std::is_same_v<bool, std::decay_t<decltype(data)>>)
                     {
                         json.append(data ? "true" : "false");
                     }
                     else if constexpr (IS_MAP_V<std::decay_t<decltype(data)>>)
                     {
                         json.push_back('{');
                         size_t count2 = 0;
                         for (const auto& [key, value] : data)
                         {
                             if (count2++ > 0)
                             {
                                 json.push_back(',');
                             }
                             json.push_back('\"');
                             json.append(key);
                             json.push_back('\"');
                             json.push_back(':');
                             if constexpr (std::is_same_v<std::string, std::decay_t<decltype(value)>> ||
                                           std::is_same_v<std::string_view, std::decay_t<decltype(value)>>)
                             {
                                 json.push_back('\"');
                                 if (needEscape(value))
                                 {
                                     escapeJSONString(value, json);
                                 }
                                 else
                                 {
                                     json.append(value);
                                 }
                                 json.push_back('\"');
                             }
                             else if constexpr ((std::is_arithmetic_v<std::decay_t<decltype(value)>> ||
                                                 std::is_same_v<double, std::decay_t<decltype(value)>>) &&
                                                !std::is_same_v<bool, std::decay_t<decltype(value)>>)
                             {
                                 auto [ptr, ec] = std::to_chars(buffer, buffer + sizeof(buffer), value);
                                 if (ec == std::errc())
                                 {
                                     json.append(buffer);
                                 }
                                 else
                                 {
                                     json.push_back('0');
                                 }
                                 std::fill(buffer, buffer + sizeof(buffer), '\0');
                             }
                             else if constexpr (std::is_same_v<bool, std::decay_t<decltype(value)>>)
                             {
                                 json.append(value ? "true" : "false");
                             }
                             else
                             {
                                 jsonFieldToString<std::decay_t<decltype(value)>, NOEMPTY, NOSINGLESPACE>(value, json);
                             }
                         }
                         json.push_back('}');
                     }
                     else if constexpr (IS_VECTOR_V<std::decay_t<decltype(data)>>)
                     {
                         size_t count2 = 0;
                         json.push_back('[');
                         for (const auto& v : data)
                         {
                             if (count2++ > 0)
                             {
                                 json.push_back(',');
                             }
                             if constexpr (std::is_same_v<std::string, std::decay_t<decltype(v)>> ||
                                           std::is_same_v<std::string_view, std::decay_t<decltype(v)>>)
                             {
                                 json.push_back('\"');
                                 if (needEscape(v))
                                 {
                                     escapeJSONString(v, json);
                                 }
                                 else
                                 {
                                     json.append(v);
                                 }
                                 json.push_back('\"');
                             }
                             else if constexpr ((std::is_arithmetic_v<std::decay_t<decltype(v)>> ||
                                                 std::is_same_v<double, std::decay_t<decltype(v)>>) &&
                                                !std::is_same_v<bool, std::decay_t<decltype(v)>>)
                             {
                                 auto [ptr, ec] = std::to_chars(buffer, buffer + sizeof(buffer), v);
                                 if (ec == std::errc())
                                 {
                                     json.append(buffer);
                                 }
                                 else
                                 {
                                     json.push_back('0');
                                 }

                                 std::fill(buffer, buffer + sizeof(buffer), '\0');
                             }
                             else if constexpr (std::is_same_v<bool, std::decay_t<decltype(v)>>)
                             {
                                 json.append(v ? "true" : "false");
                             }
                             else
                             {
                                 jsonFieldToString<std::decay_t<decltype(v)>, NOEMPTY, NOSINGLESPACE>(v, json);
                             }
                         }
                         json.push_back(']');
                     }
                     else
                     {
                         jsonFieldToString<std::decay_t<decltype(data)>, NOEMPTY, NOSINGLESPACE>(data, json);
                     }
                 }()),
             ...);
        },
        fields);

    json.push_back('}');
}

template<typename T, bool NOEMPTY = true, bool NOSINGLESPACE = true>
std::enable_if_t<IsReflectable<T>::value, std::string> serializeToJSON(const T& obj)
{
    constexpr auto fields = T::fields();

    if constexpr (std::tuple_size<decltype(fields)>::value == 1)
    {
        const auto& field = std::get<0>(fields);
        const auto& data = obj.*(std::get<2>(field));

        std::string json;
        json.reserve(1024);

        jsonFieldToString<std::decay_t<decltype(data)>, NOEMPTY, NOSINGLESPACE>(data, json);
        return json;
    }

    std::string json;
    json.reserve(1024);
    json.push_back('{');
    char buffer[BUFFER_SIZE] = {};

    size_t count = 0;
    std::apply(
        [&](auto&&... field)
        {
            ((
                 [&]
                 {
                     const auto& data = obj.*(std::get<2>(field));
                     if constexpr (NOEMPTY)
                     {
                         if (isEmpty(data))
                         {
                             return;
                         }
                     }

                     if constexpr (NOSINGLESPACE)
                     {
                         if (isSingleSpace(data))
                         {
                             return;
                         }
                     }

                     if (count++ > 0)
                     {
                         json.push_back(',');
                     }
                     json.append(std::get<1>(field));
                     //  If is string add quotes
                     if constexpr (std::is_same_v<std::string, std::decay_t<decltype(data)>> ||
                                   std::is_same_v<std::string_view, std::decay_t<decltype(data)>>)
                     {

                         json.push_back('"');
                         if (needEscape(data))
                         {
                             escapeJSONString(data, json);
                         }
                         else
                         {
                             json.append(data);
                         }
                         json.push_back('"');
                     }
                     else if constexpr (std::is_same_v<double, std::decay_t<decltype(data)>>)
                     {
                         // Special case: GCC 9.4 doesn't support std::to_chars(double), so we use snprintf
                         int len = std::snprintf(buffer, sizeof(buffer), "%g", data);
                         if (len > 0 && len < static_cast<int>(sizeof(buffer)))
                         {
                             json.append(buffer);
                         }
                         else
                         {
                             json.append("0");
                         }
                         std::fill(buffer, buffer + sizeof(buffer), '\0');
                     }
                     else if constexpr (std::is_arithmetic_v<std::decay_t<decltype(data)>> &&
                                        !std::is_same_v<bool, std::decay_t<decltype(data)>>)
                     {
                         // Use to_chars for ints/floats where supported
                         auto [ptr, ec] = std::to_chars(buffer, buffer + sizeof(buffer), data);
                         if (ec == std::errc())
                         {
                             json.append(buffer, ptr);
                         }
                         else
                         {
                             json.append("0");
                         }
                         std::fill(buffer, buffer + sizeof(buffer), '\0');
                     }
                     else if constexpr (std::is_same_v<bool, std::decay_t<decltype(data)>>)
                     {
                         json.append(data ? "true" : "false");
                     }
                     else if constexpr (IS_MAP_V<std::decay_t<decltype(data)>>)
                     {
                         size_t count2 = 0;
                         json.push_back('{');
                         for (const auto& [key, value] : data)
                         {
                             if (count2++ > 0)
                             {
                                 json.push_back(',');
                             }
                             json.push_back('\"');
                             json.append(key);
                             json.push_back('\"');
                             json.push_back(':');
                             if constexpr (std::is_same_v<std::string, std::decay_t<decltype(value)>> ||
                                           std::is_same_v<std::string_view, std::decay_t<decltype(value)>>)
                             {
                                 json.push_back('\"');
                                 if (needEscape(value))
                                 {
                                     escapeJSONString(value, json);
                                 }
                                 else
                                 {
                                     json.append(value);
                                 }
                                 json.push_back('\"');
                             }
                             else if constexpr ((std::is_arithmetic_v<std::decay_t<decltype(value)>> ||
                                                 std::is_same_v<double, std::decay_t<decltype(value)>>) &&
                                                !std::is_same_v<bool, std::decay_t<decltype(value)>>)
                             {
                                 auto [ptr, ec] = std::to_chars(buffer, buffer + sizeof(buffer), value);
                                 if (ec == std::errc())
                                 {
                                     json.append(buffer);
                                 }
                                 else
                                 {
                                     json.push_back('0');
                                 }
                                 std::fill(buffer, buffer + sizeof(buffer), '\0');
                             }
                             else if constexpr (std::is_same_v<bool, std::decay_t<decltype(value)>>)
                             {
                                 json.append(value ? "true" : "false");
                             }
                             else if constexpr (IS_VECTOR_V<std::decay_t<decltype(value)>>)
                             {
                                 size_t count3 = 0;
                                 json.push_back('[');
                                 for (const auto& v : value)
                                 {
                                     if (count3++ > 0)
                                     {
                                         json.push_back(',');
                                     }
                                     if constexpr (std::is_same_v<std::string, std::decay_t<decltype(v)>> ||
                                                   std::is_same_v<std::string_view, std::decay_t<decltype(v)>>)
                                     {
                                         json.push_back('\"');
                                         if (needEscape(v))
                                         {
                                             escapeJSONString(v, json);
                                         }
                                         else
                                         {
                                             json.append(v);
                                         }
                                         json.push_back('\"');
                                     }
                                     else if constexpr ((std::is_arithmetic_v<std::decay_t<decltype(value)>> ||
                                                         std::is_same_v<double, std::decay_t<decltype(value)>>) &&
                                                        !std::is_same_v<bool, std::decay_t<decltype(value)>>)
                                     {
                                         auto [ptr, ec] = std::to_chars(buffer, buffer + sizeof(buffer), v);
                                         if (ec == std::errc())
                                         {
                                             json.append(buffer);
                                         }
                                         else
                                         {
                                             json.push_back('0');
                                         }
                                         std::fill(buffer, buffer + sizeof(buffer), '\0');
                                     }
                                     else if constexpr (std::is_same_v<bool, std::decay_t<decltype(v)>>)
                                     {
                                         json.append(v ? "true" : "false");
                                     }
                                     else
                                     {
                                         jsonFieldToString<std::decay_t<decltype(v)>, NOEMPTY, NOSINGLESPACE>(v, json);
                                     }
                                 }
                                 json.push_back(']');
                             }

                             else
                             {
                                 jsonFieldToString<std::decay_t<decltype(value)>, NOEMPTY, NOSINGLESPACE>(value, json);
                             }
                         }
                         json.push_back('}');
                     }
                     else
                     {
                         jsonFieldToString<std::decay_t<decltype(data)>, NOEMPTY, NOSINGLESPACE>(data, json);
                     }
                 }()),
             ...);
        },
        fields);

    json.push_back('}');
    return json;
}

template<typename T, bool NOEMPTY, bool NOSINGLESPACE>
std::enable_if_t<IS_VECTOR_V<T>, void> serializeToJSON(const T& vec, std::string& json)
{
    size_t count = 0;
    char buffer[BUFFER_SIZE] = {};
    json.push_back('[');
    for (const auto& v : vec)
    {
        if (count++ > 0)
        {
            json.push_back(',');
        }

        if constexpr (std::is_same_v<std::string, std::decay_t<decltype(v)>> ||
                      std::is_same_v<std::string_view, std::decay_t<decltype(v)>>)
        {
            json.push_back('"');
            if (needEscape(v))
            {
                escapeJSONString(v, json);
            }
            else
            {
                json.append(v);
            }
            json.push_back('"');
        }
        else if constexpr (std::is_arithmetic_v<std::decay_t<decltype(v)>>)
        {
            auto [ptr, ec] = std::to_chars(buffer, buffer + sizeof(buffer), v);
            if (ec == std::errc())
            {
                json.append(buffer);
            }
            else
            {
                json.push_back('0');
            }
            std::fill(buffer, buffer + sizeof(buffer), '\0');
        }
        else if constexpr (std::is_same_v<bool, std::decay_t<decltype(v)>>)
        {
            json.append(v ? "true" : "false");
        }
        else
        {
            jsonFieldToString<std::decay_t<decltype(v)>, NOEMPTY, NOSINGLESPACE>(v, json);
        }
    }
    json.push_back(']');
}

template<typename T, bool NOEMPTY, bool NOSINGLESPACE>
std::string jsonFieldToString(const T& obj)
{
    return serializeToJSON<T, NOEMPTY, NOSINGLESPACE>(obj);
}

template<typename T, bool NOEMPTY, bool NOSINGLESPACE>
void jsonFieldToString(const T& obj, std::string& json)
{
    serializeToJSON<T, NOEMPTY, NOSINGLESPACE>(obj, json);
}

#endif // _REFLECTIVE_JSON_HPP
