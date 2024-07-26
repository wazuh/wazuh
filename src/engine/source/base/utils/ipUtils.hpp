#ifndef _IP_UTILS_H
#define _IP_UTILS_H

#include <iostream>

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
bool checkStrIsIPv4(const std::string& ip);

/**
 * @brief Check if a string is a valid IPv6 address
 *
 * @param ip String to be checked
 * @return true if the string is a valid IPv6 address
 * @return false if the string is not a valid IPv6 address
 */
bool checkStrIsIPv6(const std::string& ip);

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

} // namespace utils::ip

#endif // _IP_UTILS_H
