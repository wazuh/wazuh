#ifndef _OP_BUILDER_HELPER_FILTER_H
#define _OP_BUILDER_HELPER_FILTER_H

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
 * @brief Create `string_equal` helper function that filters events with a string
 * field equals to a value.
 *
 * The filter checks if a field in the JSON event is equal to a value.
 * Only pass events if the fields are equal (case sensitive) and the values are a string.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `string_equal` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringEqual(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `string_not_equal` helper function that filters events with a string
 * field not equals to a value.
 *
 * The filter checks if a field in the JSON event is not  equal to a value.
 * Only do not pass events if the fields are equal (case sensitive) and the values are a
 * string.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `string_not_equal` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringNotEqual(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `string_greater` helper function that filters events with a string
 * field greater than a value.
 *
 * The filter checks if the JSON event field <field> is greater than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `string_greater` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringGreaterThan(const Reference& targetField,
                                          const std::vector<OpArg>& opArgs,
                                          const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `string_greater_or_equal` helper function that filters events with a string
 * field less or equals than a value.
 *
 * The filter checks if the JSON event field <field> is greater or equals than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `string_greater_or_equal` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringGreaterThanEqual(const Reference& targetField,
                                               const std::vector<OpArg>& opArgs,
                                               const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `string_less` helper function that filters events with a string
 * field less than a value.
 *
 * The filter checks if the JSON event field <field> is less than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `string_less` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringLessThan(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `string_less_or_equal` helper function that filters events with a string
 * field less or equals than a value.
 *
 * The filter checks if the JSON event field <field> is less or equals than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `string_less_or_equal` filter.
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
 * @return Expression The lifter with the `int_equal` filter.
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
 * @return Expression The lifter with the `int_not_equal` filter.
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
 * @return Expression The lifter with the `int_less` filter.
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
 * @return Expression The lifter with the `int_less_or_equal` filter.
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
 * @return Expression The lifter with the `int_greater` filter.
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
 * @return Expression The lifter with the `int_greater_or_equal` filter.
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
 * @return FilterOp The lifter with the `binary_and` filter.
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
 * @brief Create `ip_cidr_match` helper function that filters events if the field
 * is in the specified CIDR range.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return Expression The lifter with the `ip_cidr_match` filter.
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
 * @brief Create `array_contains` helper function that filters events if the field
 * is an array and contains one of the specified values.
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
 * @brief Create the helper function `array_contains` that filters events if the field
 * is an array and contains at least one of the specified values.
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
 * @brief Create `array_not_contains` helper function that filters events if the field
 * is an array and does not contains any of the specified values.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 *
 * @throws std::runtime_error if cannot create the filter.
 */
FilterOp opBuilderHelperNotContains(const Reference& targetField,
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
 * @brief Evaluate whether the current environment is test or production.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 *
 * @throws std::runtime_error if cannot create the filter.
 */
FilterOp opBuilderHelperIsTestSession(const Reference& targetField,
                                      const std::vector<OpArg>& opArgs,
                                      const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create the helper function `array_not_contains_any` that filters events if the field
 * is an array and does not contain at least one of the specified values.
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
 * @brief Create `match_value` helper function that filters events which field
 * value is present in the specified definition array.
 * <field>: +match_value/$<definition_array>|$<array_reference>
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
 * @brief Create `exists_key_in` helper function that filters events which field
 * value is present as a key in the specified definition object.
 * <field>: +exists_key_in/$<definition_object>|$<object_reference>
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
 * @brief Checks if all the specified keys from the target field (an object) are present in the given list.
 * It verifies whether the elements in the list are included as keys in the target object.
 * If any key from the target object is missing in the list, the validation fails.
 * The function does not require that all keys in the list be present in the target field,
 * but all keys from the target field must be in the list.
 * If any element in the list is not a string, or if the target object is missing any keys from the list, the validation
 * fails. This helper is particularly useful for ensuring that all required keys are present in the object and are
 * strictly enforced in the list.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing the list of keys to be evaluated
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return FilterOp
 */
FilterOp opBuilderHelperKeysExistInList(const Reference& targetField,
                                        const std::vector<OpArg>& opArgs,
                                        const std::shared_ptr<const IBuildCtx>& buildCtx);

} // namespace builder::builders::opfilter

#endif // _OP_BUILDER_HELPER_FILTER_H
