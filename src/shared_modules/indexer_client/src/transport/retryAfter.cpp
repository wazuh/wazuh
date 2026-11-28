/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "transport/retryAfter.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <limits>

// Retry-After (RFC 9110 §10.2.3): delta-seconds or an HTTP-date (§5.6.7) in one of its three forms. Everything here is
// byte-level: no locale, no strptime/std::get_time/mktime, so neither the global locale nor the TZ variable can change
// the result.

namespace indexer_client::detail
{
    namespace
    {
        constexpr std::array<std::string_view, 7> SHORT_DAYS {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"};
        constexpr std::array<std::string_view, 7> LONG_DAYS {
            "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"};
        constexpr std::array<std::string_view, 12> MONTHS {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

        constexpr bool isOws(char c) noexcept
        {
            return c == ' ' || c == '\t' || c == '\r' || c == '\n';
        }

        constexpr bool isDigit(char c) noexcept
        {
            return c >= '0' && c <= '9';
        }

        std::string_view trim(std::string_view s) noexcept
        {
            while (!s.empty() && isOws(s.front()))
            {
                s.remove_prefix(1);
            }
            while (!s.empty() && isOws(s.back()))
            {
                s.remove_suffix(1);
            }
            return s;
        }

        /// Byte cursor over the value; every reader consumes on success and fails without side effects otherwise.
        class Cursor final
        {
        public:
            explicit Cursor(std::string_view text) noexcept
                : m_text(text)
            {
            }

            bool literal(std::string_view expected) noexcept
            {
                if (m_text.substr(0, expected.size()) != expected)
                {
                    return false;
                }
                m_text.remove_prefix(expected.size());
                return true;
            }

            /// Exactly `width` digits.
            bool digits(std::size_t width, int& out) noexcept
            {
                if (m_text.size() < width)
                {
                    return false;
                }
                int value = 0;
                for (std::size_t i = 0; i < width; ++i)
                {
                    if (!isDigit(m_text[i]))
                    {
                        return false;
                    }
                    value = value * 10 + (m_text[i] - '0');
                }
                m_text.remove_prefix(width);
                out = value;
                return true;
            }

            /// One of `names`, case-sensitive (HTTP-date names are case-sensitive, §5.6.7); returns its index.
            template<std::size_t N>
            bool oneOf(const std::array<std::string_view, N>& names, int& index) noexcept
            {
                for (std::size_t i = 0; i < N; ++i)
                {
                    if (literal(names[i]))
                    {
                        index = static_cast<int>(i);
                        return true;
                    }
                }
                return false;
            }

            /// hh:mm:ss
            bool clock(int& hour, int& minute, int& second) noexcept
            {
                return digits(2, hour) && literal(":") && digits(2, minute) && literal(":") && digits(2, second);
            }

            bool atEnd() const noexcept
            {
                return m_text.empty();
            }

        private:
            std::string_view m_text;
        };

        struct CivilTime final
        {
            int year {0};
            int month {0}; ///< 1..12
            int day {0};
            int hour {0};
            int minute {0};
            int second {0};
        };

        constexpr bool isLeap(int year) noexcept
        {
            return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        }

        bool valid(const CivilTime& t) noexcept
        {
            constexpr std::array<int, 12> DAYS_IN_MONTH {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
            if (t.month < 1 || t.month > 12 || t.day < 1 || t.hour > 23 || t.minute > 59 || t.second > 60)
            {
                return false;
            }
            const int days = DAYS_IN_MONTH[static_cast<std::size_t>(t.month - 1)] + (t.month == 2 && isLeap(t.year));
            return t.day <= days;
        }

        /// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's days_from_civil).
        std::int64_t daysFromCivil(std::int64_t y, unsigned m, unsigned d) noexcept
        {
            y -= m <= 2;
            const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
            const auto yoe = static_cast<unsigned>(y - era * 400);
            const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
            const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
            return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
        }

        std::int64_t epochSeconds(const CivilTime& t) noexcept
        {
            return daysFromCivil(t.year, static_cast<unsigned>(t.month), static_cast<unsigned>(t.day)) * 86400 +
                   t.hour * 3600 + t.minute * 60 + t.second;
        }

        /// IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT".
        bool imfFixdate(std::string_view text, CivilTime& t) noexcept
        {
            Cursor c(text);
            int ignored = 0;
            int month = 0;
            if (!(c.oneOf(SHORT_DAYS, ignored) && c.literal(", ") && c.digits(2, t.day) && c.literal(" ") &&
                  c.oneOf(MONTHS, month) && c.literal(" ") && c.digits(4, t.year) && c.literal(" ") &&
                  c.clock(t.hour, t.minute, t.second) && c.literal(" GMT") && c.atEnd()))
            {
                return false;
            }
            t.month = month + 1;
            return true;
        }

        /// Obsolete RFC 850: "Sunday, 06-Nov-94 08:49:37 GMT". A two-digit year that would lie more than 50 years in
        /// the future is the most recent past year with those digits (RFC 9110 §5.6.7).
        bool rfc850(std::string_view text, CivilTime& t, std::int64_t nowYear) noexcept
        {
            Cursor c(text);
            int ignored = 0;
            int month = 0;
            int yy = 0;
            if (!(c.oneOf(LONG_DAYS, ignored) && c.literal(", ") && c.digits(2, t.day) && c.literal("-") &&
                  c.oneOf(MONTHS, month) && c.literal("-") && c.digits(2, yy) && c.literal(" ") &&
                  c.clock(t.hour, t.minute, t.second) && c.literal(" GMT") && c.atEnd()))
            {
                return false;
            }
            t.month = month + 1;
            std::int64_t year = (nowYear / 100) * 100 + yy;
            if (year > nowYear + 50)
            {
                year -= 100;
            }
            t.year = static_cast<int>(year);
            return true;
        }

        /// asctime: "Sun Nov  6 08:49:37 1994" (day padded with a space).
        bool asctime(std::string_view text, CivilTime& t) noexcept
        {
            Cursor c(text);
            int ignored = 0;
            int month = 0;
            if (!(c.oneOf(SHORT_DAYS, ignored) && c.literal(" ") && c.oneOf(MONTHS, month) && c.literal(" ")))
            {
                return false;
            }
            if (!(c.literal(" ") ? c.digits(1, t.day) : c.digits(2, t.day)))
            {
                return false;
            }
            if (!(c.literal(" ") && c.clock(t.hour, t.minute, t.second) && c.literal(" ") && c.digits(4, t.year) &&
                  c.atEnd()))
            {
                return false;
            }
            t.month = month + 1;
            return true;
        }

        /// Year (UTC) of a POSIX time, without gmtime (civil_from_days).
        std::int64_t yearOf(std::time_t now) noexcept
        {
            std::int64_t z = static_cast<std::int64_t>(now) / 86400;
            if (static_cast<std::int64_t>(now) % 86400 < 0)
            {
                --z;
            }
            z += 719468;
            const std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
            const auto doe = static_cast<unsigned>(z - era * 146097);
            const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
            const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
            const unsigned mp = (5 * doy + 2) / 153;
            const unsigned m = mp < 10 ? mp + 3 : mp - 9;
            return static_cast<std::int64_t>(yoe) + era * 400 + (m <= 2);
        }

        Duration secondsCapped(std::int64_t seconds, Duration cap) noexcept
        {
            if (seconds <= 0)
            {
                return Duration {0};
            }
            const auto capSeconds = cap.count() / 1000;
            if (seconds > capSeconds)
            {
                return cap;
            }
            return std::min(Duration {seconds * 1000}, cap);
        }
    } // namespace

    std::optional<Duration> parseRetryAfter(std::string_view value, std::time_t now, Duration cap) noexcept
    {
        if (cap < Duration {0})
        {
            cap = Duration {0};
        }
        value = trim(value);
        if (value.empty())
        {
            return std::nullopt;
        }

        if (isDigit(value.front()))
        {
            // delta-seconds = 1*DIGIT. An overflowing number is still a valid (huge) delay: the cap applies.
            std::uint64_t seconds = 0;
            const auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(), seconds);
            if (end != value.data() + value.size())
            {
                return std::nullopt;
            }
            if (ec == std::errc::result_out_of_range ||
                seconds > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
            {
                return cap;
            }
            if (ec != std::errc {})
            {
                return std::nullopt;
            }
            return secondsCapped(static_cast<std::int64_t>(seconds), cap);
        }

        CivilTime date;
        if (!(imfFixdate(value, date) || rfc850(value, date, yearOf(now)) || asctime(value, date)) || !valid(date))
        {
            return std::nullopt;
        }
        return secondsCapped(epochSeconds(date) - static_cast<std::int64_t>(now), cap);
    }
} // namespace indexer_client::detail
