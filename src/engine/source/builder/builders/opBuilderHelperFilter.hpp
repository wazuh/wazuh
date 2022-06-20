/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OP_BUILDER_HELPER_FILTER_H
#define _OP_BUILDER_HELPER_FILTER_H

#include <optional>
#include <any>

#include "builderTypes.hpp"
#include "expression.hpp"
#include <utils/stringUtils.hpp>

/*
 * The helper filter, builds a lifter that will chain rxcpp filter operation
 * Rxcpp filter expects a function that returns bool.
 *
 * Warning: this function never should throw an exception.
 */

namespace builder::internals::builders
{

/**
 * @brief Create `exists` helper function that filters events that contains specified field.
 *
 * The filter checks if a field exists in the JSON event `e`.
 * @param definition The filter definition.
 * @return Expression The lifter with the `exists` filter.
 */
Expression opBuilderHelperExists(std::any definition);

/**
 * @brief Create `not_exists` helper function that filters events that not contains specified field.
 *
 * The filter checks if a field not exists in the JSON event `e`.
 * @param def The filter definition.
 * @return Expression The lifter with the `not_exists` filter.
 */
Expression opBuilderHelperNotExists(std::any definition);

//*************************************************
//*           String filters                      *
//*************************************************

/**
 * @brief Compares a string of the event against another string that may or may not belong to the event `e`
 *
 * @param key The key/path of the field to be compared
 * @param op The operator to be used for the comparison. Operators are:
 * - `=`: checks if the field is equal to the value
 * - `!`: checks if the field is not equal to the value
 * - `<`: checks if the field is less than the value
 * - `>`: checks if the field is greater than the value
 * - `l`: checks if the field is less than or equal to the value
 * - `g`: checks if the field is greater than or equal to the value
 * @param e The event containing the field to be compared
 * @param refValue The key/path of the field to be compared against (optional)
 * @param value The string to be compared against (optional)
 * @return true if the comparison is true
 * @return false in other case
 * @note If `refExpStr` is not provided, the comparison will be against the value of `expectedStr`
 */
inline bool opBuilderHelperStringComparison(const std::string  key, char op, base::Event& e,
                                                 std::optional<std::string> refValue,
                                                 std::optional<std::string> value);

/**
 * @brief Create `s_eq` helper function that filters events with a string
 * field equals to a value.
 *
 * The filter checks if a field in the JSON event is equal to a value.
 * Only pass events if the fields are equal (case sensitive) and the values are a string.
 * @param def The filter definition.
 * @return Expression The lifter with the `s_eq` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
Expression opBuilderHelperStringEQ(std::any definition);

/**
 * @brief Create `s_ne` helper function that filters events with a string
 * field not equals to a value.
 *
 * The filter checks if a field in the JSON event is not  equal to a value.
 * Only do not pass events if the fields are equal (case sensitive) and the values are a string.
 * @param def The filter definition.
 * @return Expression The lifter with the `s_ne` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
Expression opBuilderHelperStringNE(std::any definition);

/**
 * @brief Create `s_gt` helper function that filters events with a string
 * field greater than a value.
 *
 * The filter checks if the JSON event field <field> is greater than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param def The filter definition.
 * @return Expression The lifter with the `s_gt` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
Expression opBuilderHelperStringGT(std::any definition);

/**
 * @brief Create `s_ge` helper function that filters events with a string
 * field less or equals than a value.
 *
 * The filter checks if the JSON event field <field> is greater or equals than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param def The filter definition.
 * @return Expression The lifter with the `s_ge` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
Expression opBuilderHelperStringGE(std::any definition);

/**
 * @brief Create `s_lt` helper function that filters events with a string
 * field less than a value.
 *
 * The filter checks if the JSON event field <field> is less than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param def The filter definition.
 * @return Expression The lifter with the `s_lt` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
Expression opBuilderHelperStringLT(std::any definition);

/**
 * @brief Create `s_le` helper function that filters events with a string
 * field less or equals than a value.
 *
 * The filter checks if the JSON event field <field> is less or equals than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param def The filter definition.
 * @return Expression The lifter with the `s_le` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
Expression opBuilderHelperStringLE(std::any definition);

//*************************************************
//*              Int filters                      *
//*************************************************

/**
 * @brief Compares a integer of the event against another integer that may or may not
 * belong to the event `e`
 *
 * @param field The key/path of the field to be compared
 * @param op The operator to be used for the comparison. Operators are:
 * - `=`: checks if the field is equal to the value
 * - `!`: checks if the field is not equal to the value
 * - `<`: checks if the field is less than the value
 * - `>`: checks if the field is greater than the value
 * - `l`: checks if the field is less than or equal to the value
 * - `g`: checks if the field is greater than or equal to the value
 * @param e The event containing the field to be compared
 * @param refValue The key/path of the field to be compared against (optional)
 * @param value The integer to be compared against (optional)
 * @return true if the comparison is true
 * @return false in other case
 * @note If `refValue` is not provided, the comparison will be against the value of
 * `value`
 */
inline bool opBuilderHelperIntComparison(const std::string field, char op,
                                         base::Event & e,
                                         std::optional<std::string> refValue,
                                         std::optional<int> value);

/**
 * @brief Builds helper integer equal operation.
 * Checks that the field is equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is equal to a value.
 * Only pass events if the fields are equal and the values are a integer.
 * @param def Definition of the operation to be built
 * @return Expression The lifter with the `i_eq` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
Expression opBuilderHelperIntEqual(std::any definition);

/**
 * @brief Builds helper integer not equal operation.
 * Checks that the field is not equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is not equal to a value.
 * Only pass events if the fields are not equal and the values are a integer.
 * @param def Definition of the operation to be built
 * @return Expression The lifter with the `i_ne` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
Expression opBuilderHelperIntNotEqual(std::any definition);

/**
 * @brief Builds helper integer less than operation.
 * Checks that the field is less than to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is less than a value.
 * Only pass events if the fields are less than and the values are a integer.
 * @param def Definition of the operation to be built
 * @return Expression The lifter with the `i_lt` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
Expression opBuilderHelperIntLessThan(std::any definition);

/**
 * @brief Builds helper integer less than equal operation.
 * Checks that the field is less than equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is less than equal a value.
 * Only pass events if the fields are less than equal and the values are a integer.
 * @param def Definition of the operation to be built
 * @return Expression The lifter with the `i_le` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
Expression opBuilderHelperIntLessThanEqual(std::any definition);

/**
 * @brief Builds helper integer greater than operation.
 * Checks that the field is greater than to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is greater than a value.
 * Only pass events if the fields are greater than and the values are a integer.
 * @param def Definition of the operation to be built
 * @return Expression The lifter with the `i_gt` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */

Expression opBuilderHelperIntGreaterThan(std::any definition);

/**
 * @brief Builds helper integer greater than equal operation.
 * Checks that the field is greater than equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is greater than equal a value.
 * Only pass events if the fields are greater than equal and the values are a integer.
 * @param def Definition of the operation to be built
 * @return Expression The lifter with the `i_ge` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
Expression opBuilderHelperIntGreaterThanEqual(std::any definition);

/**
 * @brief Builds helper regex match operation.
 * Checks that the field value matches a regular expression
 *
 * @param def Definition of the operation to be built
 * @return Expression The lifter with the `regex` filter.
 */
Expression opBuilderHelperRegexMatch(std::any definition);

/**
 * @brief Builds helper regex not match operation.
 * Checks that the field value doesn't match a regular expression
 *
 * @param def Definition of the operation to be built
 * @return Expression The lifter with the `regex_not` filter.
 */
Expression opBuilderHelperRegexNotMatch(std::any definition);

/**
 * @brief Create `ip_cidr` helper function that filters events if the field
 * is in the specified CIDR range.
 *
 * @param def The filter definition.
 * @return Expression The lifter with the `ip_cidr` filter.
 * @throw  std::runtime_error if the parameter is not a cidr.
 */
Expression opBuilderHelperIPCIDR(std::any definition);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_HELPER_FILTER_H
