/*
 * Wazuh shared modules utils - JWT agent authentication profile
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/// @file strictJsonObject.hpp
/// One-pass strict parser for the flat JSON objects of the JWT profiles (JOSE header, claims set):
/// an exact allowlist of members, each with a fixed type (string or non-negative integer), no
/// duplicates, no nesting, no extra members, root must be an object, UTF-8 validated. Built on
/// rapidjson's SAX Reader so nothing is materialised beyond the expected fields -- the strictness a
/// generic JWT library cannot offer (jwtCppSpike_test.cpp pins why). Reused by every profile.

#pragma once

#include <rapidjson/error/error.h>
#include <rapidjson/reader.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

namespace jwt_profile::v1
{
    struct JsonField
    {
        std::string_view name;
        bool integer; ///< true: non-negative int64 required; false: string required
    };

    /// @tparam N number of fields in the allowlist (<= 16).
    template<std::size_t N>
    class StrictJsonObject final
    {
        static_assert(N <= 16, "field bitmask is 16 bits wide");

    public:
        using Fields = std::array<JsonField, N>;

        /// @return true iff `json` is exactly an object with all N fields, each of the right type.
        static bool parse(const Fields& fields, std::string_view json, StrictJsonObject& out) noexcept
        {
            out = StrictJsonObject {};
            // rapidjson's StringStream needs a NUL-terminated buffer; JSON text never legitimately
            // contains a raw NUL, and one inside a string would trip the parser anyway.
            std::string buffer;
            try
            {
                buffer.assign(json.data(), json.size());
            }
            catch (...)
            {
                return false;
            }
            Sink sink {fields, out};
            rapidjson::Reader reader;
            rapidjson::StringStream stream {buffer.c_str()};
            const auto result = reader.Parse<rapidjson::kParseValidateEncodingFlag>(stream, sink);
            return !result.IsError() && sink.complete() && !sink.failed;
        }

        std::string_view str(std::size_t i) const noexcept
        {
            return m_strings[i];
        }
        std::int64_t num(std::size_t i) const noexcept
        {
            return m_integers[i];
        }

    private:
        struct Sink : rapidjson::BaseReaderHandler<rapidjson::UTF8<>, Sink>
        {
            Sink(const Fields& f, StrictJsonObject& o)
                : fields(f)
                , out(o)
            {
            }
            const Fields& fields;
            StrictJsonObject& out;
            int depth {0};
            int current {-1};
            std::uint16_t seen {0};
            bool failed {false};

            bool fail() noexcept
            {
                failed = true;
                return false;
            }
            bool complete() const noexcept
            {
                return depth == 0 && seen == static_cast<std::uint16_t>((1u << N) - 1u);
            }

            bool StartObject()
            {
                return ++depth == 1 || fail();
            }
            bool EndObject(rapidjson::SizeType)
            {
                return depth-- == 1 || fail();
            }
            bool Key(const char* name, rapidjson::SizeType len, bool)
            {
                current = -1;
                for (std::size_t i = 0; i < N; ++i)
                {
                    if (fields[i].name.size() == len && std::memcmp(fields[i].name.data(), name, len) == 0)
                    {
                        current = static_cast<int>(i);
                        break;
                    }
                }
                if (current < 0 || (seen & (1u << current)) != 0)
                {
                    return fail(); // unknown or duplicate member
                }
                seen |= static_cast<std::uint16_t>(1u << current);
                return true;
            }
            bool String(const char* value, rapidjson::SizeType len, bool)
            {
                if (depth != 1 || current < 0 || fields[current].integer)
                {
                    return fail();
                }
                try
                {
                    out.m_strings[current].assign(value, len);
                }
                catch (...)
                {
                    return fail();
                }
                return true;
            }
            bool integer(std::int64_t value)
            {
                if (depth != 1 || current < 0 || !fields[current].integer || value < 0)
                {
                    return fail();
                }
                out.m_integers[current] = value;
                return true;
            }
            bool Int(int v)
            {
                return integer(v);
            }
            bool Uint(unsigned v)
            {
                return integer(v);
            }
            bool Int64(std::int64_t v)
            {
                return integer(v);
            }
            bool Uint64(std::uint64_t v)
            {
                return v <= static_cast<std::uint64_t>(INT64_MAX) ? integer(static_cast<std::int64_t>(v)) : fail();
            }
            bool Null()
            {
                return fail();
            }
            bool Bool(bool)
            {
                return fail();
            }
            bool Double(double)
            {
                return fail();
            }
            bool RawNumber(const char*, rapidjson::SizeType, bool)
            {
                return fail();
            }
            bool StartArray()
            {
                return fail();
            }
            bool EndArray(rapidjson::SizeType)
            {
                return fail();
            }
        };

        std::array<std::string, N> m_strings {};
        std::array<std::int64_t, N> m_integers {};
    };
} // namespace jwt_profile::v1
