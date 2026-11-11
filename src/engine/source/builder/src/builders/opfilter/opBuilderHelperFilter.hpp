// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef OP_BUILDER_HELPER_FILTER_H
#define OP_BUILDER_HELPER_FILTER_H

#include "builders/types.hpp"

/*
 * The helper filter, builds a lifter that will chain rxcpp filter operation
 * Rxcpp filter expects a function that returns bool.
 *
 * Warning: this function never should throw an exception.
 */

namespace builder::builders::opfilter
{

//*************************************************
//*           String filters                      *
//*************************************************

/**
 * @brief Create `string_eq` helper function that filters events with a string
 * field equals to a value.
 *
 * The filter checks if a field in the JSON event is equal to a value.
 * Only pass events if the fields are equal (case sensitive) and the values are a string.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `string_eq` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringEqual(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `string_ne` helper function that filters events with a string
 * field not equals to a value.
 *
 * The filter checks if a field in the JSON event is not  equal to a value.
 * Only do not pass events if the fields are equal (case sensitive) and the values are a
 * string.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `string_ne` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringNotEqual(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `string_gt` helper function that filters events with a string
 * field greater than a value.
 *
 * The filter checks if the JSON event field <field> is greater than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `string_gt` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringGreaterThan(const Reference& targetField,
                                          const std::vector<OpArg>& opArgs,
                                          const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `string_gte` helper function that filters events with a string
 * field less or equals than a value.
 *
 * The filter checks if the JSON event field <field> is greater or equals than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `string_gte` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringGreaterThanEqual(const Reference& targetField,
                                               const std::vector<OpArg>& opArgs,
                                               const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `string_lt` helper function that filters events with a string
 * field less than a value.
 *
 * The filter checks if the JSON event field <field> is less than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `string_lt` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringLessThan(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `string_lte` helper function that filters events with a string
 * field less or equals than a value.
 *
 * The filter checks if the JSON event field <field> is less or equals than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `string_lte` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringLessThanEqual(const Reference& targetField,
                                            const std::vector<OpArg>& opArgs,
                                            const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create the `starts_with` helper function that allows to check if a field string
 * starts as a given one.
 *
 * The filter passes if both strings are equal (case sensitive) on the first N characters.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return xpression The lifter with the `starts_with` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringStarts(const Reference& targetField,
                                     const std::vector<OpArg>& opArgs,
                                     const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create the `contains` helper function that allows to check if a field string
 * contains another one.
 *
 * The filter passes if the first one contains all of the seccond one.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return xpression The lifter with the `contains` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringContains(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx);

//*************************************************
//*              Number filters                      *
//*************************************************

/**
 * @brief Builds helper number equal operation.
 * Checks that the field is equal to an number or another numeric field
 *
 * The filter checks if a field in the JSON event is equal to a value.
 * Only pass events if the fields are equal and the values are a number.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `double_equal` filter.
 * @throw std::runtime_error if the parameter is not a number.
 */
FilterOp opBuilderHelperNumberEqual(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper number not equal operation.
 * Checks that the field is not equal to an number or another numeric field
 *
 * The filter checks if a field in the JSON event is not equal to a value.
 * Only pass events if the fields are not equal and the values are a number.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `double_not_equal` filter.
 * @throw std::runtime_error if the parameter is not a number.
 */
FilterOp opBuilderHelperNumberNotEqual(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper number less than operation.
 * Checks that the field is less than to an number or another numeric field
 *
 * The filter checks if a field in the JSON event is less than a value.
 * Only pass events if the fields are less than and the values are a number.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `double_less` filter.
 * @throw std::runtime_error if the parameter is not a number.
 */
FilterOp opBuilderHelperNumberLessThan(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper number less than equal operation.
 * Checks that the field is less than equal to an number or another numeric field
 *
 * The filter checks if a field in the JSON event is less than equal a value.
 * Only pass events if the fields are less than equal and the values are a number.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `double_less_or_equal` filter.
 * @throw std::runtime_error if the parameter is not a number.
 */
FilterOp opBuilderHelperNumberLessThanEqual(const Reference& targetField,
                                            const std::vector<OpArg>& opArgs,
                                            const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper number greater than operation.
 * Checks that the field is greater than to an number or another numeric field
 *
 * The filter checks if a field in the JSON event is greater than a value.
 * Only pass events if the fields are greater than and the values are a number.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `double_greater` filter.
 * @throw std::runtime_error if the parameter is not a number.
 */

FilterOp opBuilderHelperNumberGreaterThan(const Reference& targetField,
                                          const std::vector<OpArg>& opArgs,
                                          const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper number greater than equal operation.
 * Checks that the field is greater than equal to an number or another numeric field
 *
 * The filter checks if a field in the JSON event is greater than equal a value.
 * Only pass events if the fields are greater than equal and the values are a number.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `double_greater_or_equal` filter.
 * @throw std::runtime_error if the parameter is not a number.
 */
FilterOp opBuilderHelperNumberGreaterThanEqual(const Reference& targetField,
                                               const std::vector<OpArg>& opArgs,
                                               const std::shared_ptr<const IBuildCtx>& buildCtx);

//*************************************************
//*              Int filters                      *
//*************************************************

/**
 * @brief Builds helper integer equal operation.
 * Checks that the field is equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is equal to a value.
 * Only pass events if the fields are equal and the values are a integer.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `int_eq` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
FilterOp opBuilderHelperIntEqual(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper integer not equal operation.
 * Checks that the field is not equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is not equal to a value.
 * Only pass events if the fields are not equal and the values are a integer.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `int_ne` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
FilterOp opBuilderHelperIntNotEqual(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper integer less than operation.
 * Checks that the field is less than to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is less than a value.
 * Only pass events if the fields are less than and the values are a integer.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `int_lt` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
FilterOp opBuilderHelperIntLessThan(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper integer less than equal operation.
 * Checks that the field is less than equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is less than equal a value.
 * Only pass events if the fields are less than equal and the values are a integer.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `int_lte` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
FilterOp opBuilderHelperIntLessThanEqual(const Reference& targetField,
                                         const std::vector<OpArg>& opArgs,
                                         const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper integer greater than operation.
 * Checks that the field is greater than to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is greater than a value.
 * Only pass events if the fields are greater than and the values are a integer.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `int_gt` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */

FilterOp opBuilderHelperIntGreaterThan(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper integer greater than equal operation.
 * Checks that the field is greater than equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is greater than equal a value.
 * Only pass events if the fields are greater than equal and the values are a integer.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `int_gte` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
FilterOp opBuilderHelperIntGreaterThanEqual(const Reference& targetField,
                                            const std::vector<OpArg>& opArgs,
                                            const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper Binary and operation.
 * Convert the argument to a integer and do a binary and with the field value.
 *
 * Note: only hexa string is supported
 * @param targetField target field of the helper
 * @param opArgs  vector of parameters as present in the raw definition
 * @param buildCtx handler with definitions
 * @return FilterOp The lifter with the `has_any_bit` filter.
 */
FilterOp opBuilderHelperBinaryAnd(const Reference& targetField,
                                  const std::vector<OpArg>& opArgs,
                                  const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper regex match operation.
 * Checks that the field value matches a regular expression
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `regex` filter.
 */
FilterOp opBuilderHelperRegexMatch(const Reference& targetField,
                                   const std::vector<OpArg>& opArgs,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper regex not match operation.
 * Checks that the field value doesn't match a regular expression
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `regex_not` filter.
 */
FilterOp opBuilderHelperRegexNotMatch(const Reference& targetField,
                                      const std::vector<OpArg>& opArgs,
                                      const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `in_cidr` helper function that filters events if the field
 * is in the specified CIDR range.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `in_cidr` filter.
 */
FilterOp opBuilderHelperIPCIDR(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_public_ip` helper function that filters events if the field
 * is a public IP address.
 *
 * This helper filters events if the field is a public IP address IPv4 or if the field is a
 * IPv6 address then a filter is created to check if the field is not a special IPv6 address (like loopback, link-local,
 * etc.).
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return FilterOp The lifter with the `is_public_ip` filter.
 */
FilterOp opBuilderHelperPublicIP(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create the `array_contains_all` helper function: passes when the target field is an array that
 * contains every one of the given values (a missing reference argument makes it fail).
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 *
 * @throws std::runtime_error if cannot create the filter.
 */
FilterOp opBuilderHelperContains(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create the `array_contains_any` helper function: passes when the target field is an array that
 * contains at least one of the given values (missing reference arguments are skipped).
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 *
 * @throws std::runtime_error if cannot create the filter.
 */
FilterOp opBuilderHelperContainsAny(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Checks if the string stored in the field ends with the value provided.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 *
 * @throws std::runtime_error if cannot create the filter.
 */
FilterOp opBuilderHelperEndsWith(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Check if the reference parameter contains a valid IPv4 address.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 *
 * @throws std::runtime_error if cannot create the filter.
 */
FilterOp opBuilderHelperIsIpv4(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Check if the reference parameter contains a valid IPv6 address.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 *
 * @throws std::runtime_error if cannot create the filter.
 */
FilterOp opBuilderHelperIsIpv6(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create the `array_contains_none` helper function: passes when the target field is an array that
 * contains none of the given values (a missing reference argument makes it fail).
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 *
 * @throws std::runtime_error if cannot create the filter.
 */
FilterOp opBuilderHelperNotContainsAny(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx);

//*************************************************
//*                Type filters                   *
//*************************************************

/**
 * @brief Create `is_number` helper function that filters events which field is not of the
 * expected type.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 */
FilterOp opBuilderHelperIsNumber(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_not_number` helper function that filters events which field is not of
 * the expected type.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 */
FilterOp opBuilderHelperIsNotNumber(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_string` helper function that filters events which field is not of
 * the expected type.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 */
FilterOp opBuilderHelperIsString(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_not_string` helper function that filters events which field is not
 * of the expected type.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 */
FilterOp opBuilderHelperIsNotString(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_boolean` helper function that filters events which field is not of the
 * expected type.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 */
FilterOp opBuilderHelperIsBool(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_not_boolean` helper function that filters events which field is not of
 * the expected type.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 */
FilterOp opBuilderHelperIsNotBool(const Reference& targetField,
                                  const std::vector<OpArg>& opArgs,
                                  const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_array` helper function that filters events which field is not of
 * the expected type.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 */
FilterOp opBuilderHelperIsArray(const Reference& targetField,
                                const std::vector<OpArg>& opArgs,
                                const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_not_array` helper function that filters events which field is not
 * of the expected type.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 */
FilterOp opBuilderHelperIsNotArray(const Reference& targetField,
                                   const std::vector<OpArg>& opArgs,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_object` helper function that filters events which field is not of
 * the expected type.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 */
FilterOp opBuilderHelperIsObject(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_not_object` helper function that filters events which field is not
 * of the expected type.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 */
FilterOp opBuilderHelperIsNotObject(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_null` helper function that filters events which field is not of the
 * expected type.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 */
FilterOp opBuilderHelperIsNull(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_not_null` helper function that filters events which field is not of
 * the expected type.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 */
FilterOp opBuilderHelperIsNotNull(const Reference& targetField,
                                  const std::vector<OpArg>& opArgs,
                                  const std::shared_ptr<const IBuildCtx>& buildCtx);

//*************************************************
//*              Definition filters               *
//*************************************************

/**
 * @brief Create `one_of` helper function that filters events which field
 * value is present in the specified definition array.
 * <field>: +one_of/$<definition_array>|$<array_reference>
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 */
FilterOp opBuilderHelperMatchValue(const Reference& targetField,
                                   const std::vector<OpArg>& opArgs,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_key_of` helper function that filters events which field
 * value is present as a key in the specified definition object.
 * <field>: +is_key_of/$<definition_object>|$<object_reference>
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 */
FilterOp opBuilderHelperMatchKey(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create the `has_only_keys` helper function: passes when every top-level key of the target object is in
 * the given list of strings (the list may contain keys the object does not have; an empty object passes).
 * Fails when the target is missing or not an object, when the list reference is missing or not an array of
 * strings, or when the object has a key outside the list.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing the list of keys to be evaluated
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 */
FilterOp opBuilderHelperKeysExistInList(const Reference& targetField,
                                        const std::vector<OpArg>& opArgs,
                                        const std::shared_ptr<const IBuildCtx>& buildCtx);

//*************************************************
//*              Array and Policy filters         *
//*************************************************

/**
 * @brief Create `array_length` helper function that checks if an array has a specific length.
 *
 * This helper verifies that the target field is an array and has the specified length.
 * The length is provided as a numeric parameter.
 *
 * @param targetField Reference to the array field to check
 * @param opArgs Vector containing one numeric argument: the expected length
 * @param buildCtx Build context
 * @return FilterOp The filter operation
 *
 * @throws std::runtime_error if parameter is not a valid integer
 */
FilterOp opBuilderHelperArrayLength(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `index_unclassified_events` helper function that checks policy settings and integration category.
 *
 * This helper returns true if:
 * - The policy has indexUnclassifiedEvents flag set to true AND
 * - $wazuh.integration.category equals "unclassified"
 *
 * Otherwise, it returns false.
 *
 * @param targetField Reference to $wazuh.integration.category. Any other field is rejected at build-time.
 * @param opArgs Vector of operation arguments (empty for this helper)
 * @param buildCtx Build context containing policy configuration
 * @return FilterOp The filter operation
 */
FilterOp opBuilderHelperIndexUnclassifiedEvents(const Reference& targetField,
                                                const std::vector<OpArg>& opArgs,
                                                const std::shared_ptr<const IBuildCtx>& buildCtx);

} // namespace builder::builders::opfilter

#endif // OP_BUILDER_HELPER_FILTER_H
