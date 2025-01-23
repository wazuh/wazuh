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

#include <charconv>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <unordered_map>

#define REFLECTABLE(...)                                                                                               \
    static constexpr auto fields()                                                                                     \
    {                                                                                                                  \
        return std::make_tuple(__VA_ARGS__);                                                                           \
    }

#define MAKE_FIELD(keyLiteral, memberPtr)                                                                              \
    std::make_tuple(std::string_view {keyLiteral}, std::string_view {"\"" keyLiteral "\":"}, memberPtr)

static std::array<const char*, 256> escapeTable = []
{
    std::array<const char*, 256> table {};
    for (int i = 0; i < 256; ++i)
    {
        table[i] = nullptr;
    }

    table['"'] = R"("\"")";
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
            static char buffer[256][7];
            snprintf(buffer[i], 7, "\\u%04x", i);
            table[i] = buffer[i];
        }
    }
    return table;
}();
bool needEscape(std::string_view input)
{
    for (auto c : input)
    {
        if (escapeTable[c])
        {
            return true;
        }
    }
    return false;
}
inline void escapeJSONString(std::string_view input, std::string& output)
{

    for (auto c : input)
    {
        if (escapeTable[c])
        {
            output.append(escapeTable[c]);
        }
        else
        {
            output.push_back(c);
        }
    }
}

template<typename T>
struct is_map : std::false_type
{
};

template<typename K, typename V, typename... Args>
struct is_map<std::map<K, V, Args...>> : std::true_type
{
};

template<typename K, typename V, typename... Args>
struct is_map<std::unordered_map<K, V, Args...>> : std::true_type
{
};

template<typename T>
constexpr bool is_map_v = is_map<std::decay_t<T>>::value;

template<typename T>
struct is_vector : std::false_type
{
};

template<typename T, typename... Args>
struct is_vector<std::vector<T, Args...>> : std::true_type
{
};

template<typename T>
constexpr bool is_vector_v = is_vector<std::decay_t<T>>::value;

template<typename T, typename = void>
struct IsReflectable : std::false_type
{
};

template<typename T>
struct IsReflectable<T, std::void_t<decltype(T::fields())>> : std::true_type
{
};

template<typename T>
std::enable_if_t<!IsReflectable<T>::value, bool> isEmpty(const T&)
{
    return false;
}

// Para std::string
inline bool isEmpty(std::string_view value)
{
    return value.empty();
}

// Para std::unordered_map (vacío si está vacío)
template<typename K, typename V>
bool isEmpty(const std::unordered_map<K, V>& map)
{
    return map.empty();
}

// Para std::unordered_map (vacío si está vacío)
template<typename K, typename V>
bool isEmpty(const std::map<K, V>& map)
{
    return map.empty();
}

// Para std::unordered_map (vacío si está vacío)
template<typename V>
bool isEmpty(const std::vector<V>& vector)
{
    return vector.empty();
}

// Para objetos reflejables: vacío si todos sus campos están vacíos
template<typename T>
std::enable_if_t<IsReflectable<T>::value, bool> isEmpty(const T& obj)
{
    constexpr auto fields = T::fields();
    bool allEmpty = true;
    std::apply([&](auto&&... field) { ((allEmpty = allEmpty && isEmpty(obj.*(std::get<2>(field)))), ...); }, fields);
    return allEmpty;
}

// === FUNCTIONS TO CONVERT TO JSON ===

template<typename K, typename V>
std::string jsonFieldToString(const std::unordered_map<K, V>& map)
{
    std::string json = "{";
    size_t count = 0;
    char buffer[32] = {};
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
        }
        else
        {
            json.append(jsonFieldToString(value));
        }
    }
    json.push_back('}');
    return json;
}

template<typename T>
std::string jsonFieldToString(const T& obj);
template<typename T>
void jsonFieldToString(const T& obj, std::string& json);

template<typename T>
std::enable_if_t<IsReflectable<T>::value, void> serializeToJSON(const T& obj, std::string& json)
{
    json.push_back('{');
    constexpr auto fields = T::fields();
    char buffer[32] = {};

    size_t count = 0;
    std::apply(
        [&](auto&&... field)
        {
            ((
                 [&]
                 {
                     const auto& value = obj.*(std::get<2>(field));
                     if (!isEmpty(value))
                     {
                         if (count++ > 0)
                         {
                             json.push_back(',');
                         }
                         json.append(std::get<1>(field));
                         //  If is string add quotes
                         if constexpr (std::is_same_v<std::string, std::decay_t<decltype(value)>> ||
                                       std::is_same_v<std::string_view, std::decay_t<decltype(value)>>)
                         {

                             json.push_back('"');
                             if (needEscape(value))
                             {
                                 escapeJSONString(value, json);
                             }
                             else
                             {
                                 json.append(value);
                             }
                             json.push_back('"');
                         }
                         else if constexpr ((std::is_arithmetic_v<std::decay_t<decltype(value)>> ||
                                             std::is_same_v<double, std::decay_t<decltype(value)>>)&&!std::
                                                is_same_v<bool, std::decay_t<decltype(value)>>)
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
                         }
                         else if constexpr (std::is_same_v<bool, std::decay_t<decltype(value)>>)
                         {
                             json.append(value ? "true" : "false");
                         }
                         else if constexpr (is_map_v<std::decay_t<decltype(value)>>)
                         {
                             json.push_back('{');
                             size_t count2 = 0;
                             for (const auto& [key, value] : value)
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
                                                     std::is_same_v<double, std::decay_t<decltype(value)>>)&&!std::
                                                        is_same_v<bool, std::decay_t<decltype(value)>>)
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
                                 }
                                 else if constexpr (std::is_same_v<bool, std::decay_t<decltype(value)>>)
                                 {
                                     json.append(value ? "true" : "false");
                                 }
                                 else
                                 {
                                     jsonFieldToString(value, json);
                                 }
                             }
                             json.push_back('}');
                         }
                         else if constexpr (is_vector_v<std::decay_t<decltype(value)>>)
                         {
                             size_t count2 = 0;
                             json.push_back('[');
                             for (const auto& v : value)
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
                                 else if constexpr ((std::is_arithmetic_v<decltype(v)> ||
                                                     std::is_same_v<const double&, decltype(v)>)&&!std::
                                                        is_same_v<bool, std::decay_t<decltype(v)>>)
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
                                 }
                                 else if constexpr (std::is_same_v<bool, std::decay_t<decltype(v)>>)
                                 {
                                     json.append(v ? "true" : "false");
                                 }
                                 else
                                 {
                                     jsonFieldToString(v, json);
                                 }
                             }
                             json.push_back(']');
                         }
                         else
                         {
                             jsonFieldToString(value, json);
                         }
                     }
                 }()),
             ...);
        },
        fields);

    json.push_back('}');
}

template<typename T>
std::enable_if_t<IsReflectable<T>::value, std::string> serializeToJSON(const T& obj)
{
    std::string json;
    json.reserve(1024);
    json.push_back('{');
    constexpr auto fields = T::fields();
    char buffer[32] = {};

    size_t count = 0;
    std::apply(
        [&](auto&&... field)
        {
            ((
                 [&]
                 {
                     const auto& value = obj.*(std::get<2>(field));
                     if (!isEmpty(value))
                     {
                         if (count++ > 0)
                         {
                             json.push_back(',');
                         }
                         json.append(std::get<1>(field));
                         //  If is string add quotes
                         if constexpr (std::is_same_v<std::string, std::decay_t<decltype(value)>> ||
                                       std::is_same_v<std::string_view, std::decay_t<decltype(value)>>)
                         {

                             json.push_back('"');
                             if (needEscape(value))
                             {
                                 escapeJSONString(value, json);
                             }
                             else
                             {
                                 json.append(value);
                             }
                             json.push_back('"');
                         }
                         else if constexpr ((std::is_arithmetic_v<std::decay_t<decltype(value)>> ||
                                             std::is_same_v<double, std::decay_t<decltype(value)>>)&&!std::
                                                is_same_v<bool, std::decay_t<decltype(value)>>)
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
                         }
                         else if constexpr (std::is_same_v<bool, std::decay_t<decltype(value)>>)
                         {
                             json.append(value ? "true" : "false");
                         }
                         else if constexpr (is_map_v<std::decay_t<decltype(value)>>)
                         {
                             size_t count2 = 0;
                             json.push_back('{');
                             for (const auto& [key, value] : value)
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
                                                     std::is_same_v<double, std::decay_t<decltype(value)>>)&&!std::
                                                        is_same_v<bool, std::decay_t<decltype(value)>>)
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
                                 }
                                 else if constexpr (std::is_same_v<bool, std::decay_t<decltype(value)>>)
                                 {
                                     json.append(value ? "true" : "false");
                                 }
                                 else if constexpr (is_vector_v<std::decay_t<decltype(value)>>)
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
                                                             std::is_same_v<double,
                                                                            std::decay_t<decltype(value)>>)&&!std::
                                                                is_same_v<bool, std::decay_t<decltype(value)>>)
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
                                         }
                                         else if constexpr (std::is_same_v<bool, std::decay_t<decltype(v)>>)
                                         {
                                             json.append(v ? "true" : "false");
                                         }
                                         else
                                         {
                                             jsonFieldToString(v, json);
                                         }
                                     }
                                     json.push_back(']');
                                 }

                                 else
                                 {
                                     jsonFieldToString(value, json);
                                 }
                             }
                             json.push_back('}');
                         }
                         else
                         {
                             jsonFieldToString(value, json);
                         }
                     }
                 }()),
             ...);
        },
        fields);

    json.push_back('}');
    return json;
}

template<typename T>
std::string jsonFieldToString(const T& obj)
{
    return serializeToJSON(obj);
}

template<typename T>
void jsonFieldToString(const T& obj, std::string& json)
{
    serializeToJSON(obj, json);
}

#endif // _REFLECTIVE_JSON_HPP
