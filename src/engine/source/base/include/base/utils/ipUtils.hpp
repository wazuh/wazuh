#ifndef _IP_UTILS_H
#define _IP_UTILS_H

#include <array>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string_view>
#include <unordered_map>

namespace utils::ip
{

/**
 * @brief Convert a ipv4 string to a uint32_t
 *
 * @param ip String to be converted (format x.x.x.x)
 * @return uint32_t ipv4
 * @throws std::invalid_argument if the ip is not valid
 */
uint32_t IPv4ToUInt(const std::string& ip);

/**
 * @brief convert a mask IPv4 string to a uint32_t
 *
 * @param mask network mask format x.x.x.x or x (i.e. 255.0.0.0 its equivalent to 8)
 * @return uint32_t mask
 * @throws std::invalid_argument if the mask is not valid
 */
uint32_t IPv4MaskUInt(const std::string& mask);

// TODO: implement
/**
 * @brief Convert a ipv6 string to a uint128_t
 * @param ip String to be converted
 * @return uint128_t ipv6
 */
// uint128_t IPv6ToUInt(const std::string ip);

/**
 * @brief Check if a string is a valid IPv4 address
 *
 * @param ip String to be checked
 * @return true if the string is a valid IPv4 address
 * @return false if the string is not a valid IPv4 address
 */
bool checkStrIsIPv4(const std::string& ip, std::array<uint8_t, 4>* outBytes = nullptr);

/**
 * @brief Check if a string is a valid IPv6 address
 *
 * @param ip String to be checked
 * @return true if the string is a valid IPv6 address
 * @return false if the string is not a valid IPv6 address
 */
bool checkStrIsIPv6(const std::string& ip, std::array<uint8_t, 16>* outBytes = nullptr);

/**
 * @brief Check if a IPv4 is a special address
 *
 * A special IPv4 address can be a loopback address or a private address
 * @param ip
 * @return true if the ip is a special address
 * @throw std::invalid_argument if the ip is not valid
 */
bool isSpecialIPv4Address(const std::string& ip);

/**
 * @brief Checks if the given IPv6 address is a special address.
 *
 * A special IPv6 address can be:
 * - loopback address (::1/128)
 * - link-local address (fe80::/10),
 * - Unique Local Address (ULA) (fc00::/7).
 *
 * @param ip The IPv6 address to check.
 * @return True if the address is a special IPv6 address, false otherwise.
 * @throws std::invalid_argument If the given IP address is not a valid IPv6 address.
 */
bool isSpecialIPv6Address(const std::string& ip);

/**
 * @brief Normalize a candidate IANA protocol name to canonical lookup form:
 * - lower-case
 * - spaces/underscores replaced with '-'
 * - common aliases: "icmpv6"->"ipv6-icmp", "udp-lite"/"udp_lite" → "udplite", "ip-in-ip" → "ipip"
 */
std::string normalizeIanaProtocolName(std::string_view in);

/**
 * @brief Returns the IANA number for a given protocol name (strict: names only).
 * If the name is unknown (e.g., application-layer like "smtp"), returns std::nullopt.
 */
std::optional<uint8_t> ianaProtocolNameToNumber(std::string_view name);

/**
 * @brief Lookup the canonical IANA protocol keyword for a given code.
 * Returns std::nullopt if the code is unassigned/experimental/reserved or unknown.
 *
 * @param code IANA protocol number (0..255)
 * @return std::optional<std::string_view> Canonical keyword if found, std::nullopt otherwise.
 */
std::optional<std::string_view> ianaProtocolNumberToName(uint8_t code);

} // namespace utils::ip

#endif // _IP_UTILS_H
