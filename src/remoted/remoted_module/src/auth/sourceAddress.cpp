/*
 * Wazuh remoted HTTPS source-address authorization
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sourceAddress.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace
{
    // Parse an address to raw bytes, matching OS_IsValidIP's forms: strips an IPv6 zone id
    // ("fe80::1%eth0") and unmaps "::ffff:x.x.x.x" to plain IPv4. Returns the family, or AF_UNSPEC.
    int parseAddress(std::string text, std::array<std::uint8_t, 16>& out, std::size_t& length)
    {
        const auto zone = text.find('%');
        if (zone != std::string::npos)
        {
            text.erase(zone);
        }

        in_addr v4 {};
        if (inet_pton(AF_INET, text.c_str(), &v4) == 1)
        {
            std::memcpy(out.data(), &v4, sizeof(v4));
            length = sizeof(v4);
            return AF_INET;
        }

        in6_addr v6 {};
        if (inet_pton(AF_INET6, text.c_str(), &v6) == 1)
        {
            if (IN6_IS_ADDR_V4MAPPED(&v6))
            {
                std::memcpy(out.data(), &v6.s6_addr[12], 4); // trailing 4 bytes are the IPv4 address
                length = 4;
                return AF_INET;
            }

            std::memcpy(out.data(), &v6, sizeof(v6));
            length = sizeof(v6);
            return AF_INET6;
        }

        return AF_UNSPEC;
    }

    // Dotted IPv4 netmask ("255.255.0.0") to prefix length. False if not a contiguous mask.
    bool ipv4NetmaskToPrefix(const std::string& text, std::size_t& prefixBits)
    {
        in_addr mask {};
        if (inet_pton(AF_INET, text.c_str(), &mask) != 1)
        {
            return false;
        }

        std::uint32_t host = ntohl(mask.s_addr);
        std::size_t bits = 0;
        while (host & 0x80000000u)
        {
            ++bits;
            host <<= 1;
        }

        if (host != 0)
        {
            return false; // ones after the first zero -> non-contiguous, not a valid netmask
        }

        prefixBits = bits;
        return true;
    }

    // Whether the first prefixBits of a and b (same length) are equal.
    bool prefixesEqual(const std::array<std::uint8_t, 16>& a,
                       const std::array<std::uint8_t, 16>& b,
                       std::size_t length,
                       std::size_t prefixBits)
    {
        if (prefixBits > length * 8)
        {
            return false;
        }

        const std::size_t fullBytes = prefixBits / 8;
        for (std::size_t i = 0; i < fullBytes; ++i)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        const std::size_t remainingBits = prefixBits % 8;
        if (remainingBits != 0)
        {
            const std::uint8_t mask = static_cast<std::uint8_t>(0xFF << (8 - remainingBits));
            if ((a[fullBytes] & mask) != (b[fullBytes] & mask))
            {
                return false;
            }
        }

        return true;
    }
}

namespace remoted::auth
{

    bool sourceAddressAllowed(std::string_view allowedSpec, std::string_view peerAddress)
    {
        // "any" or an empty column: unrestricted (case-insensitive).
        const bool isAny = allowedSpec.size() == 3 && (allowedSpec[0] == 'a' || allowedSpec[0] == 'A') &&
                           (allowedSpec[1] == 'n' || allowedSpec[1] == 'N') &&
                           (allowedSpec[2] == 'y' || allowedSpec[2] == 'Y');
        if (allowedSpec.empty() || isAny)
        {
            return true;
        }

        std::array<std::uint8_t, 16> peerBytes {};
        std::size_t peerLength = 0;
        const int peerFamily = parseAddress(std::string {peerAddress}, peerBytes, peerLength);
        if (peerFamily == AF_UNSPEC)
        {
            return false; // Can't identify the peer -> can't say it's allowed.
        }

        // Split an optional "/prefix" or "/netmask" suffix off the spec.
        const std::string spec {allowedSpec};
        const auto slash = spec.find('/');
        const std::string netText = slash == std::string::npos ? spec : spec.substr(0, slash);

        std::array<std::uint8_t, 16> netBytes {};
        std::size_t netLength = 0;
        const int netFamily = parseAddress(netText, netBytes, netLength);
        if (netFamily == AF_UNSPEC || netFamily != peerFamily)
        {
            return false; // Malformed spec, or a different family than the peer (v4 vs v6).
        }

        std::size_t prefixBits = netLength * 8; // A bare address is a host route (/32 or /128).
        if (slash != std::string::npos)
        {
            const std::string prefixText = spec.substr(slash + 1);
            if (prefixText.empty())
            {
                return false;
            }

            // "/16" (prefix) first, then "/255.255.0.0" (netmask).
            std::size_t consumed = 0;
            bool havePrefix = false;
            try
            {
                const auto value = std::stoul(prefixText, &consumed);
                if (consumed == prefixText.size())
                {
                    prefixBits = static_cast<std::size_t>(value);
                    havePrefix = true;
                }
            }
            catch (const std::exception&)
            {
                // not an integer -> try the netmask form below
            }

            if (!havePrefix && !(netFamily == AF_INET && ipv4NetmaskToPrefix(prefixText, prefixBits)))
            {
                return false;
            }

            if (prefixBits > netLength * 8)
            {
                return false;
            }
        }

        return prefixesEqual(peerBytes, netBytes, peerLength, prefixBits);
    }

} // namespace remoted::auth
